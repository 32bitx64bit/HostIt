package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hostit/server/internal/appstore"
	"hostit/shared/apitypes"
	"hostit/shared/crypto"
	"hostit/shared/emailcfg"
	"hostit/shared/logging"
	"hostit/shared/netutil"
	"hostit/shared/protocol"
	"hostit/shared/relay"
	"hostit/shared/udpfair"
	"hostit/shared/version"
)

const (
	routeProtoTCP  = "tcp"
	routeProtoUDP  = "udp"
	routeProtoBoth = "both"
)

const (
	smtpPortStandard      = 25
	smtpPortSubmissionTLS = 465
	smtpPortSubmission    = 587
)

const (
	mailDialTimeout        = 10 * time.Second
	tcpKeepAliveInterval   = 15 * time.Second
	mailRelayIdleTimeout   = 2 * time.Minute
	probeDefaultTTL        = 30 * time.Second
	writeDeadlineShort     = 2 * time.Second
	writeDeadlineStandard  = 5 * time.Second
	readDeadlineStandard   = 45 * time.Second
	authDeadline           = 5 * time.Second
	pingInterval           = 5 * time.Second
	healthCheckInterval    = 10 * time.Second
	healthCheckTimeout     = 45 * time.Second
	maxControlConnLifetime = 24 * time.Hour
	proxyIdleTimeout       = 5 * time.Minute
	udpRegisterTimeout     = 60 * time.Second
	// Clock-skew/replay window for authenticated UDP registers.
	udpRegisterAuthWindow = 30 * time.Second
	// Keep the last authenticated UDP path alive across a short control-plane
	// reconnect. A replacement registration is bound to a fresh control nonce,
	// so it can safely cancel this expiry without relying on source IP.
	udpControlLossGrace   = 15 * time.Second
	domainShutdownTimeout = 5 * time.Second
	nettestTimeout        = 2 * time.Second
	bwTestTimeout         = 5 * time.Second
	emailProbeAllowTTL    = time.Minute
	// Byte-counter flush cadence for dashboard hot paths.
	dashBatchInterval = 100 * time.Millisecond
)

var handshakeDeadline = 15 * time.Second

type agentSession struct {
	conn              net.Conn
	cancel            context.CancelFunc
	agentID           string
	remoteAddr        string
	connectTime       time.Time
	identityPublicKey []byte
	controlNonce      crypto.UDPControlNonce
	// features is the negotiated capability intersection for this session.
	features []string
	writeMu  sync.Mutex
}

type pendingTCPEntry struct {
	mu        sync.Mutex
	conn      net.Conn
	ready     chan struct{}
	done      chan struct{}
	readyOnce sync.Once
	doneOnce  sync.Once

	// owner is the agent that must claim this pairing on the data plane.
	owner string
	// controlRemote is the control-session peer addr when TypeConnect was sent.
	controlRemote string
	// pairToken is a one-time secret sent only on the control channel; the
	// agent must present it on the data connection to claim the pair.
	pairToken []byte
}

const pairTokenLen = 16

func newPendingTCPEntry() *pendingTCPEntry {
	return &pendingTCPEntry{
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
}

// newPendingTCPPair creates a pending public↔agent pairing bound to the
// owning agent's live control session.
func newPendingTCPPair(owner, controlRemote string) *pendingTCPEntry {
	token := make([]byte, pairTokenLen)
	if _, err := rand.Read(token); err != nil {
		// Extremely unlikely; fall back to a non-empty deterministic token
		// so pairing still requires presenting something non-empty.
		copy(token, []byte("hostit-pair-fallback"))
	}
	e := newPendingTCPEntry()
	e.owner = owner
	e.controlRemote = controlRemote
	e.pairToken = token
	return e
}

func (p *pendingTCPEntry) cancel() {
	if p == nil {
		return
	}
	p.mu.Lock()
	conn := p.conn
	p.conn = nil
	p.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	p.doneOnce.Do(func() {
		close(p.done)
	})
}

func (p *pendingTCPEntry) deliver(conn net.Conn) {
	if p == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
		if conn != nil {
			_ = conn.Close()
		}
		return
	default:
	}
	if p.conn != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	p.conn = conn
	p.readyOnce.Do(func() {
		close(p.ready)
	})
}

func (p *pendingTCPEntry) take() net.Conn {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	conn := p.conn
	p.conn = nil
	return conn
}

type Server struct {
	cfg      ServerConfig
	appStore *appstore.Store

	derivedKeys map[string][]byte

	// baseKey is the deployment-wide encryption key (PBKDF2 of the token);
	// derived at most once instead of per route/HELLO.
	baseKeyOnce sync.Once
	baseKey     []byte

	// Per-agent UDP state, keyed by agent ID. Published copy-on-write by the
	// registry mutation helpers; forwarding goroutines read it lock-free.
	udpAgents atomic.Pointer[map[string]*agentUDPState]
	// udpAgentsMu serializes the complete load-clone-store transaction. An
	// atomic pointer alone does not make concurrent copy-on-write updates safe.
	udpAgentsMu    sync.Mutex
	udpGraceTimers map[string]*udpGraceTimer

	mu            sync.RWMutex
	udpDataConn   *net.UDPConn
	udpEgress     *serverUDPEgress
	controlLn     net.Listener
	dataLn        net.Listener
	domainHTTPLn  net.Listener
	domainHTTPSLn net.Listener

	publicTCP map[string]net.Listener
	// publicUDP is the mutable source of truth, guarded by s.mu. publicUDPSnap
	// holds a copy-on-write snapshot for the lock-free downstream UDP read path.
	publicUDP         map[string]*net.UDPConn
	publicUDPSnap     atomic.Pointer[map[string]*net.UDPConn]
	domainHTTPServer  *http.Server
	domainHTTPSServer *http.Server
	domainCerts       *domainCertManager
	domains           *domainManager
	domainProxyCache  sync.Map

	pendingTCP map[pendingTCPKey]*pendingTCPEntry

	clientIDCounter uint64

	maxConnsPerRoute int
	connSemaphores   sync.Map

	pongCh       chan []byte
	emailProbeCh chan []byte

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// stopping is set before Stop snapshots listeners. Route mutations that
	// could add a goroutine/listener must reject work once it becomes true.
	stopping atomic.Bool

	dash *dashState

	routeCache     atomic.Value
	nextRouteEpoch uint64 // guarded by mu; zero is reserved for uninitialized routes

	sessionsMu sync.Mutex
	sessions   map[string]*agentSession

	probeOutboundMu      sync.Mutex
	probeOutboundTargets map[string]time.Time

	lastAgentConnectAt    time.Time
	lastAgentDisconnectAt time.Time

	dynamicRoutes   map[string]dynamicRouteEntry
	dynamicPortLow  int
	dynamicPortHigh int

	counters counterRegistry

	// helloDebounce coalesces rapid route mutations into one HELLO broadcast.
	helloMu      sync.Mutex
	helloPending bool
	helloTimer   *time.Timer

	// registeredAgentsCache avoids hitting SQLite on every dashboard poll.
	registeredAgentsMu    sync.Mutex
	registeredAgentsCache map[string]int64
	registeredAgentsAt    time.Time

	udpDrops atomic.Uint64
}

type agentUDPState struct {
	addr         netip.AddrPort
	lastSeen     atomic.Int64 // unix nano
	sessionID    crypto.UDPSessionID
	crypto       *agentUDPCrypto
	controlNonce crypto.UDPControlNonce
}

type udpGraceTimer struct {
	controlNonce crypto.UDPControlNonce
	timer        *time.Timer
}

const maxSeenUDPRegistersPerAgent = 32

// udpRegisterReplayCache keeps replay bookkeeping bounded per authenticated
// identity. It is owned by the single acceptAgentUDP goroutine and therefore
// needs no lock. A flooded identity can temporarily deny only its own new
// registrations; it cannot grow a global map or evict another agent's proofs.
type udpRegisterReplayCache struct {
	entries map[string]*udpRegisterReplayBucket
}

type udpRegisterReplayBucket struct {
	controlNonce crypto.UDPControlNonce
	entries      map[crypto.UDPRegisterKey]int64
}

func newUDPRegisterReplayCache() *udpRegisterReplayCache {
	return &udpRegisterReplayCache{entries: make(map[string]*udpRegisterReplayBucket)}
}

// status performs the cheap pre-verification checks for the currently cached
// control generation. A different generation must first pass live-session and
// identity verification before it is allowed to replace the bucket.
func (c *udpRegisterReplayCache) status(agentID string, controlNonce crypto.UDPControlNonce, key crypto.UDPRegisterKey, nowNano int64) (seen, full bool) {
	bucket := c.entries[agentID]
	if bucket == nil || bucket.controlNonce != controlNonce {
		return false, false
	}
	expires, ok := bucket.entries[key]
	if !ok {
		c.pruneBucket(agentID, bucket, nowNano)
		return false, len(bucket.entries) >= maxSeenUDPRegistersPerAgent
	}
	if expires < nowNano {
		delete(bucket.entries, key)
		if len(bucket.entries) == 0 {
			delete(c.entries, agentID)
		}
		return false, false
	}
	return true, false
}

func (c *udpRegisterReplayCache) record(agentID string, controlNonce crypto.UDPControlNonce, key crypto.UDPRegisterKey, expiresNano, nowNano int64) bool {
	bucket := c.entries[agentID]
	if bucket == nil || bucket.controlNonce != controlNonce {
		bucket = &udpRegisterReplayBucket{
			controlNonce: controlNonce,
			entries:      make(map[crypto.UDPRegisterKey]int64, maxSeenUDPRegistersPerAgent),
		}
		c.entries[agentID] = bucket
	} else {
		c.pruneBucket(agentID, bucket, nowNano)
		// pruneBucket removes an empty bucket from the authoritative map. Do
		// not populate that detached pointer; recreate it before recording.
		if c.entries[agentID] == nil {
			bucket = &udpRegisterReplayBucket{
				controlNonce: controlNonce,
				entries:      make(map[crypto.UDPRegisterKey]int64, maxSeenUDPRegistersPerAgent),
			}
			c.entries[agentID] = bucket
		}
	}
	if len(bucket.entries) >= maxSeenUDPRegistersPerAgent {
		return false
	}
	bucket.entries[key] = expiresNano
	return true
}

func (c *udpRegisterReplayCache) prune(nowNano int64) {
	for agentID, bucket := range c.entries {
		c.pruneBucket(agentID, bucket, nowNano)
	}
}

func (c *udpRegisterReplayCache) pruneBucket(agentID string, bucket *udpRegisterReplayBucket, nowNano int64) {
	for key, expires := range bucket.entries {
		if expires < nowNano {
			delete(bucket.entries, key)
		}
	}
	if len(bucket.entries) == 0 {
		delete(c.entries, agentID)
	}
}

// agentUDPCrypto is the server's view of one agent UDP session: it seals
// server->agent traffic and opens agent->server traffic with keys derived
// from the agent's per-run session ID. dec is only touched by the single
// acceptAgentUDP goroutine; enc is concurrency-safe.
type agentUDPCrypto struct {
	sessionID crypto.UDPSessionID
	enc       *crypto.UDPEncryptor
	dec       *crypto.UDPDecryptor
}

// encryptionBaseKey derives (once) the deployment-wide key used for TCP
// wrapping and UDP session-key derivation. Returns nil when encryption is
// not configured or derivation fails.
func (s *Server) encryptionBaseKey() []byte {
	s.baseKeyOnce.Do(func() {
		key, err := crypto.DeriveKey(s.cfg.Token, s.cfg.EncryptionAlgorithm)
		if err != nil {
			logging.Global().Errorf(logging.CatEncryption, "failed to derive encryption key: %v", err)
			return
		}
		s.baseKey = key
	})
	return s.baseKey
}

func (s *Server) sessionForAgent(agentID string) (*agentSession, bool) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	sess, ok := s.sessions[agentID]
	return sess, ok
}

// targetSession returns the session for agentID, or any session when empty.
func (s *Server) targetSession(agentID string) (*agentSession, bool) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if strings.TrimSpace(agentID) != "" {
		sess, ok := s.sessions[agentID]
		return sess, ok
	}
	for _, sess := range s.sessions {
		return sess, true
	}
	return nil, false
}

func (s *Server) isCurrentSession(agentID string, sess *agentSession) bool {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	return s.sessions[agentID] == sess
}

func (s *Server) connectedAgentIDs() []string {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	return ids
}

func (s *Server) agentConnected() bool {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	return len(s.sessions) > 0
}

func (s *Server) routeOwner(routeName string) string {
	if cache, ok := s.routeCache.Load().(map[string]routeConfig); ok {
		if rc, ok := cache[routeName]; ok && rc.owner != "" {
			return rc.owner
		}
	}
	return protocol.DefaultAgentID
}

func (s *Server) loadUDPAgents() map[string]*agentUDPState {
	if m := s.udpAgents.Load(); m != nil {
		return *m
	}
	return nil
}

// loadPublicUDP returns the lock-free snapshot of the public UDP listeners.
func (s *Server) loadPublicUDP() map[string]*net.UDPConn {
	if m := s.publicUDPSnap.Load(); m != nil {
		return *m
	}
	return nil
}

// publishPublicUDPLocked republishes the copy-on-write snapshot from the
// authoritative publicUDP map. Must be called while holding s.mu.
func (s *Server) publishPublicUDPLocked() {
	cp := make(map[string]*net.UDPConn, len(s.publicUDP))
	for k, v := range s.publicUDP {
		cp[k] = v
	}
	s.publicUDPSnap.Store(&cp)
}

// updateUDPAgentAddr publishes one authenticated endpoint generation. The
// mutex covers the whole copy-on-write transaction; callers that also hold
// sessionsMu must always acquire sessionsMu first.
func (s *Server) updateUDPAgentAddr(agentID string, addr netip.AddrPort, sessionID crypto.UDPSessionID, controlNonce crypto.UDPControlNonce, nowNano int64) {
	s.udpAgentsMu.Lock()
	defer s.udpAgentsMu.Unlock()
	s.updateUDPAgentAddrLocked(agentID, addr, sessionID, controlNonce, nowNano)
}

func (s *Server) updateUDPAgentAddrLocked(agentID string, addr netip.AddrPort, sessionID crypto.UDPSessionID, controlNonce crypto.UDPControlNonce, nowNano int64) {
	s.cancelUDPGraceLocked(agentID)
	old := s.loadUDPAgents()
	if st := old[agentID]; st != nil && st.addr == addr && st.sessionID == sessionID && st.controlNonce == controlNonce {
		st.lastSeen.Store(nowNano)
		return
	}
	st := old[agentID]
	var uc *agentUDPCrypto
	if st != nil && st.crypto != nil && st.crypto.sessionID == sessionID {
		uc = st.crypto
	} else if baseKey := s.encryptionBaseKey(); baseKey != nil {
		sc, err := crypto.NewUDPSessionCrypto(baseKey, sessionID[:], crypto.UDPDirServerToClient, crypto.UDPDirClientToServer)
		if err != nil {
			logging.Global().Errorf(logging.CatUDP, "failed to derive UDP session keys for agent %q: %v", agentID, err)
		} else {
			uc = &agentUDPCrypto{sessionID: sessionID, enc: sc.Enc, dec: sc.Dec}
			logging.Global().Infof(logging.CatUDP, "UDP session keys rotated for agent %q session %x…", agentID, sessionID[:4])
		}
	}
	next := &agentUDPState{addr: addr, sessionID: sessionID, crypto: uc, controlNonce: controlNonce}
	next.lastSeen.Store(nowNano)
	newMap := make(map[string]*agentUDPState, len(old)+1)
	for k, v := range old {
		newMap[k] = v
	}
	newMap[agentID] = next
	s.udpAgents.Store(&newMap)
}

func (s *Server) pruneUDPAgents(nowNano int64) {
	s.udpAgentsMu.Lock()
	defer s.udpAgentsMu.Unlock()
	s.pruneUDPAgentsLocked(nowNano)
}

func (s *Server) pruneUDPAgentsLocked(nowNano int64) {
	old := s.loadUDPAgents()
	if len(old) == 0 {
		return
	}
	cutoff := nowNano - int64(udpRegisterTimeout)
	var stale []string
	for id, st := range old {
		if st.lastSeen.Load() < cutoff {
			stale = append(stale, id)
		}
	}
	if len(stale) == 0 {
		return
	}
	newMap := make(map[string]*agentUDPState, len(old))
	for k, v := range old {
		newMap[k] = v
	}
	for _, id := range stale {
		logging.Global().Infof(logging.CatUDP, "Agent %q UDP address timed out after %s inactivity", id, udpRegisterTimeout)
		delete(newMap, id)
		s.cancelUDPGraceLocked(id)
	}
	s.udpAgents.Store(&newMap)
}

// scheduleUDPAgentClearLocked starts a generation-safe expiry for the UDP
// endpoint currently published for agentID. The caller must hold sessionsMu;
// this preserves the global sessionsMu -> udpAgentsMu lock order.
func (s *Server) scheduleUDPAgentClearLocked(agentID string) {
	s.udpAgentsMu.Lock()
	defer s.udpAgentsMu.Unlock()

	st := s.loadUDPAgents()[agentID]
	if st == nil {
		return
	}
	if existing := s.udpGraceTimers[agentID]; existing != nil {
		if existing.controlNonce == st.controlNonce {
			return
		}
		existing.timer.Stop()
	}
	entry := &udpGraceTimer{controlNonce: st.controlNonce}
	entry.timer = time.AfterFunc(udpControlLossGrace, func() {
		s.expireUDPAgent(agentID, entry)
	})
	s.udpGraceTimers[agentID] = entry
}

func (s *Server) expireUDPAgent(agentID string, entry *udpGraceTimer) {
	s.udpAgentsMu.Lock()
	defer s.udpAgentsMu.Unlock()
	if s.udpGraceTimers[agentID] != entry {
		return
	}
	delete(s.udpGraceTimers, agentID)
	st := s.loadUDPAgents()[agentID]
	if st == nil || st.controlNonce != entry.controlNonce {
		return
	}
	if s.removeUDPAgentLocked(agentID) {
		logging.Global().Infof(logging.CatUDP, "Agent %q UDP path expired after %s control disconnect grace", agentID, udpControlLossGrace)
	}
}

func (s *Server) cancelUDPGraceLocked(agentID string) {
	if entry := s.udpGraceTimers[agentID]; entry != nil {
		entry.timer.Stop()
		delete(s.udpGraceTimers, agentID)
	}
}

func (s *Server) removeUDPAgentLocked(agentID string) bool {
	old := s.loadUDPAgents()
	if _, ok := old[agentID]; !ok {
		return false
	}
	newMap := make(map[string]*agentUDPState, len(old)-1)
	for k, v := range old {
		if k != agentID {
			newMap[k] = v
		}
	}
	s.udpAgents.Store(&newMap)
	return true
}

func (s *Server) stopUDPGraceTimers() {
	s.udpAgentsMu.Lock()
	defer s.udpAgentsMu.Unlock()
	for id, entry := range s.udpGraceTimers {
		entry.timer.Stop()
		delete(s.udpGraceTimers, id)
	}
}

type pendingTCPKey struct {
	route  string
	client string
}

type dynamicRouteEntry struct {
	Route     RouteConfig
	CreatedAt time.Time
	Source    string
}

func makePendingTCPKey(routeName, clientID string) pendingTCPKey {
	return pendingTCPKey{route: routeName, client: clientID}
}

func (s *Server) abortPendingTCPLocked() {
	for key, entry := range s.pendingTCP {
		delete(s.pendingTCP, key)
		entry.cancel()
	}
}

// abortPendingTCPForAgentLocked cancels in-flight pairings for agentID's routes. Holds s.mu.
func (s *Server) abortPendingTCPForAgentLocked(agentID string) {
	for key, entry := range s.pendingTCP {
		if s.routeOwner(key.route) != agentID {
			continue
		}
		delete(s.pendingTCP, key)
		entry.cancel()
	}
}

func (s *Server) nextClientID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback keeps uniqueness even if entropy fails briefly.
		id := atomic.AddUint64(&s.clientIDCounter, 1)
		return "c" + strconv.FormatUint(id, 36) + hex.EncodeToString(b[:8])
	}
	return hex.EncodeToString(b[:])
}

type helloRoute struct {
	Name       string
	Proto      string
	PublicAddr string
	LocalAddr  string
	Encrypted  bool
	Algorithm  string
}

type helloPayload struct {
	Routes     map[string]helloRoute `json:"routes"`
	Email      emailcfg.Config       `json:"email,omitempty"`
	Version    string                `json:"version,omitempty"`
	PublicAddr string                `json:"public_addr,omitempty"` // tunnel server hostname/IP for apps
}

type ServerStatus struct {
	AgentConnected bool
}

type EmailRuntimeStatus struct {
	PublicInboundListening bool
	PublicInboundAddr      string
}

func (s *Server) Status() ServerStatus {
	return ServerStatus{AgentConnected: s.agentConnected()}
}

func (s *Server) EmailStatus() EmailRuntimeStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := EmailRuntimeStatus{}
	if ln := s.publicTCP[internalEmailInboundRouteName]; ln != nil {
		st.PublicInboundListening = true
		st.PublicInboundAddr = ln.Addr().String()
	}
	return st
}

type AgentNettestRequest struct {
	AgentID      string
	Count        int
	Interval     time.Duration
	Timeout      time.Duration
	PayloadBytes int
}

type AgentNettestResult struct {
	SentPackets  int     `json:"sentPackets"`
	LostPackets  int     `json:"lostPackets"`
	LossPercent  float64 `json:"lossPercent"`
	MinLatencyMs float64 `json:"minLatencyMs"`
	MaxLatencyMs float64 `json:"maxLatencyMs"`
	AvgLatencyMs float64 `json:"avgLatencyMs"`
	JitterMs     float64 `json:"jitterMs"`
	DownloadMbps float64 `json:"downloadMbps"`
	UploadMbps   float64 `json:"uploadMbps"`
	DurationMs   float64 `json:"durationMs"`
}

func (s *Server) Dashboard(now time.Time) DashboardSnapshot {
	s.mu.RLock()
	lastAgentConnectAt := s.lastAgentConnectAt
	lastAgentDisconnectAt := s.lastAgentDisconnectAt
	s.mu.RUnlock()

	agents := s.agentStatuses()
	snap := s.dash.snapshot(now, len(agents) > 0 && anyConnected(agents))
	snap.Agents = agents
	snap.Runtime = s.runtimeStats(lastAgentConnectAt, lastAgentDisconnectAt)
	return snap
}

func anyConnected(agents []AgentStatus) bool {
	for _, a := range agents {
		if a.Connected {
			return true
		}
	}
	return false
}

// agentStatuses lists connected agents plus any that only own routes.
func (s *Server) agentStatuses() []AgentStatus {
	type sessInfo struct {
		remoteAddr  string
		connectTime time.Time
	}
	s.sessionsMu.Lock()
	sess := make(map[string]sessInfo, len(s.sessions))
	for id, se := range s.sessions {
		sess[id] = sessInfo{remoteAddr: se.remoteAddr, connectTime: se.connectTime}
	}
	s.sessionsMu.Unlock()

	udp := s.loadUDPAgents()

	s.mu.RLock()
	counts := make(map[string]int)
	for _, rt := range effectiveRoutes(s.cfg, s.dynamicRoutes) {
		counts[rt.OwnerAgent()]++
	}
	emailAgent := s.cfg.EmailRouteAgent()
	domainDisabled := make(map[string]bool, len(s.cfg.DomainDisabledAgents))
	for _, id := range s.cfg.DomainDisabledAgents {
		domainDisabled[strings.TrimSpace(id)] = true
	}
	s.mu.RUnlock()

	registered := s.cachedRegisteredAgents()

	ids := make(map[string]struct{})
	for id := range sess {
		ids[id] = struct{}{}
	}
	for id := range counts {
		ids[id] = struct{}{}
	}
	for id := range registered {
		ids[id] = struct{}{}
	}

	out := make([]AgentStatus, 0, len(ids))
	for id := range ids {
		st := AgentStatus{ID: id, RouteCount: counts[id], DomainEnabled: !domainDisabled[id], EmailAgent: id == emailAgent}
		if info, ok := sess[id]; ok {
			st.Connected = true
			st.RemoteAddr = info.remoteAddr
			st.ConnectedSinceUnix = info.connectTime.Unix()
		}
		if firstSeen, ok := registered[id]; ok {
			st.Registered = true
			st.FirstSeenUnix = firstSeen
		}
		if u, ok := udp[id]; ok && u != nil {
			if time.Since(time.Unix(0, u.lastSeen.Load())) <= udpRegisterTimeout {
				st.UDPRegistered = true
			}
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) cachedRegisteredAgents() map[string]int64 {
	const ttl = 5 * time.Second
	s.registeredAgentsMu.Lock()
	defer s.registeredAgentsMu.Unlock()
	if s.registeredAgentsCache != nil && time.Since(s.registeredAgentsAt) < ttl {
		return s.registeredAgentsCache
	}
	registered := make(map[string]int64)
	if s.appStore != nil {
		if recs, err := s.appStore.ListAgents(s.ctx); err == nil {
			for _, r := range recs {
				registered[r.AgentID] = r.FirstSeen.Unix()
			}
		}
	}
	s.registeredAgentsCache = registered
	s.registeredAgentsAt = time.Now()
	return registered
}

// EffectiveRoutes returns static + synthetic + dynamic routes currently active.
func (s *Server) EffectiveRoutes() []RouteConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return effectiveRoutes(s.cfg, s.dynamicRoutes)
}

// UDPStats returns aggregate UDP drop counters for the dashboard.
func (s *Server) UDPStats() map[string]any {
	var queueStats udpfair.Stats
	if s.udpEgress != nil {
		queueStats = s.udpEgress.queue.Stats()
	}
	queueDrops := queueStats.Dropped.Overflow + queueStats.Dropped.Expired
	return map[string]any{
		"totalDrops":         s.udpDrops.Load() + queueDrops,
		"queueDrops":         queueDrops,
		"queueOverflowDrops": queueStats.Dropped.Overflow,
		"queueExpiredDrops":  queueStats.Dropped.Expired,
		"queuedPackets":      queueStats.QueuedPackets,
		"queuedBytes":        queueStats.QueuedBytes,
		"activeRoutes":       queueStats.ActiveRoutes,
		"lossPercent":        0.0, // end-to-end loss requires nettest; drops are local rejects
	}
}

// KnownAgentIDs lists agent IDs useful for assigning route ownership: the
// default agent, plus every connected, registered, or route-owning agent.
func (s *Server) KnownAgentIDs() []string {
	set := map[string]struct{}{protocol.DefaultAgentID: {}}
	for _, a := range s.agentStatuses() {
		set[a.ID] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// dropSession terminates an agent's control session if one is connected.
func (s *Server) dropSession(agentID string) {
	s.sessionsMu.Lock()
	sess := s.sessions[agentID]
	if sess != nil {
		delete(s.sessions, agentID)
	}
	// Administrative drops are intentional revocations, not transient
	// reconnects, so remove the UDP endpoint immediately.
	s.udpAgentsMu.Lock()
	s.cancelUDPGraceLocked(agentID)
	s.removeUDPAgentLocked(agentID)
	s.udpAgentsMu.Unlock()
	s.sessionsMu.Unlock()
	if sess != nil {
		if sess.cancel != nil {
			sess.cancel()
		}
		if sess.conn != nil {
			sess.conn.Close()
		}
	}
}

// clearUDPAgent removes an agent's UDP registration (copy-on-write).
func (s *Server) clearUDPAgent(agentID string) {
	s.udpAgentsMu.Lock()
	defer s.udpAgentsMu.Unlock()
	s.cancelUDPGraceLocked(agentID)
	s.removeUDPAgentLocked(agentID)
}

// controlPeerIPMatches protects legacy TCP data-pair claims when the one-time
// pair token's control peer is known. Bound UDP registration intentionally
// does not use this check because its identity proof supports split paths.
func controlPeerIPMatches(controlRemote string, udpAddr netip.AddrPort) bool {
	if controlRemote == "" || !udpAddr.IsValid() {
		return false
	}
	host, _, err := net.SplitHostPort(controlRemote)
	if err != nil {
		host = controlRemote
	}
	host = strings.Trim(host, "[]")
	cip := net.ParseIP(host)
	if cip == nil {
		return false
	}
	caddr, ok := netip.AddrFromSlice(cip)
	if !ok {
		return false
	}
	caddr = caddr.Unmap()
	uaddr := udpAddr.Addr().Unmap()
	if caddr == uaddr {
		return true
	}
	// Control over IPv4 loopback and UDP over IPv6 loopback (or vice versa).
	return caddr.IsLoopback() && uaddr.IsLoopback()
}

// OverrideAgentID renames a registered agent: it rebinds the ID in the registry,
// migrates route ownership to the new ID, and drops the old session so the agent
// reconnects and adopts it. Static config routes are migrated in memory only;
// save server.json to keep that across a restart.
func (s *Server) OverrideAgentID(ctx context.Context, oldID, newID string) error {
	oldID = strings.TrimSpace(oldID)
	newID = strings.TrimSpace(newID)
	if oldID == "" || newID == "" {
		return fmt.Errorf("old and new agent ids are required")
	}
	if oldID == newID {
		return nil
	}
	if len(newID) > crypto.MaxAgentIDLen {
		return fmt.Errorf("agent id too long")
	}
	if s.appStore == nil {
		return fmt.Errorf("agent registry is not available")
	}
	if err := s.appStore.RenameAgent(ctx, oldID, newID); err != nil {
		return err
	}
	if _, err := s.appStore.ReassignRoutesAgent(ctx, oldID, newID); err != nil {
		logging.Global().Errorf(logging.CatSystem, "override %q->%q: reassign stored routes failed: %v", oldID, newID, err)
	}

	s.mu.Lock()
	for i := range s.cfg.Routes {
		if s.cfg.Routes[i].OwnerAgent() == oldID {
			s.cfg.Routes[i].Agent = newID
		}
	}
	for name, dr := range s.dynamicRoutes {
		if dr.Route.OwnerAgent() == oldID {
			dr.Route.Agent = newID
			s.dynamicRoutes[name] = dr
		}
	}
	s.updateRouteCacheLocked()
	s.mu.Unlock()

	s.dropSession(oldID)
	s.broadcastHello()
	logging.Global().Infof(logging.CatSystem, "Agent %q overridden to %q", oldID, newID)
	return nil
}

// ForgetAgent removes a registered agent so its ID/key can be reclaimed; a
// connected agent is disconnected.
func (s *Server) ForgetAgent(ctx context.Context, agentID string) error {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return fmt.Errorf("agent id is required")
	}
	if s.appStore == nil {
		return fmt.Errorf("agent registry is not available")
	}
	if err := s.appStore.DeleteAgent(ctx, agentID); err != nil {
		return err
	}
	s.dropSession(agentID)
	logging.Global().Infof(logging.CatSystem, "Agent %q forgotten", agentID)
	return nil
}

// SetAgentDomainEnabled turns managed-domain routing on or off for one agent.
// The gateway reads this live, so no HELLO change is needed.
func (s *Server) SetAgentDomainEnabled(agentID string, enabled bool) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return
	}
	s.mu.Lock()
	filtered := make([]string, 0, len(s.cfg.DomainDisabledAgents))
	for _, id := range s.cfg.DomainDisabledAgents {
		if strings.TrimSpace(id) != agentID {
			filtered = append(filtered, id)
		}
	}
	if !enabled {
		filtered = append(filtered, agentID)
	}
	s.cfg.DomainDisabledAgents = filtered
	s.mu.Unlock()
	logging.Global().Infof(logging.CatSystem, "Agent %q managed-domain routing set to %t", agentID, enabled)
}

// SetEmailAgent assigns which agent runs the single mail service. Rebuilding the
// route cache moves the synthetic mail routes' owner, and the HELLO re-push hands
// the mail config to the new agent (and clears it from the old one).
func (s *Server) SetEmailAgent(agentID string) {
	agentID = strings.TrimSpace(agentID)
	s.mu.Lock()
	s.cfg.EmailAgent = agentID
	s.updateRouteCacheLocked()
	s.mu.Unlock()
	s.broadcastHello()
	logging.Global().Infof(logging.CatSystem, "Email service assigned to agent %q", agentID)
}

type routeConfig struct {
	enabled     bool
	isEncrypted bool
	derivedKey  []byte
	owner       string
	proto       string
	publicAddr  string
	localAddr   string
	algorithm   string
	epoch       uint64
}

func (s *Server) updateRouteCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateRouteCacheLocked()
}

func sameUDPEgressRouteConfig(a, b routeConfig) bool {
	if a.enabled != b.enabled || a.isEncrypted != b.isEncrypted || a.owner != b.owner || a.proto != b.proto || a.publicAddr != b.publicAddr || a.localAddr != b.localAddr {
		return false
	}
	if !a.isEncrypted {
		return true
	}
	return a.algorithm == b.algorithm && bytes.Equal(a.derivedKey, b.derivedKey)
}

func (s *Server) nextRouteEpochLocked() uint64 {
	s.nextRouteEpoch++
	if s.nextRouteEpoch == 0 {
		s.nextRouteEpoch++
	}
	return s.nextRouteEpoch
}

func (s *Server) updateRouteCacheLocked() {
	oldCache, _ := s.routeCache.Load().(map[string]routeConfig)
	newCache := make(map[string]routeConfig)
	for _, rt := range effectiveRoutes(s.cfg, s.dynamicRoutes) {
		rc := routeConfig{
			enabled:     rt.IsEnabled(),
			isEncrypted: rt.IsEncrypted(),
			derivedKey:  s.derivedKeys[rt.Name],
			owner:       rt.OwnerAgent(),
			proto:       rt.Proto,
			publicAddr:  rt.PublicAddr,
			localAddr:   rt.LocalAddr,
			algorithm:   s.cfg.EncryptionAlgorithm,
		}
		if old, ok := oldCache[rt.Name]; ok && old.epoch != 0 && sameUDPEgressRouteConfig(old, rc) {
			rc.epoch = old.epoch
		} else {
			rc.epoch = s.nextRouteEpochLocked()
		}
		newCache[rt.Name] = rc
	}
	s.routeCache.Store(newCache)
	s.publishPublicUDPLocked()
}

func (s *Server) getRouteConfig(name string) (routeConfig, bool) {
	cache, _ := s.routeCache.Load().(map[string]routeConfig)
	rc, ok := cache[name]
	return rc, ok
}

// Permitted SMTP destinations: standard ports only, no private/loopback.
func isAllowedOutboundSMTPTarget(addr *net.TCPAddr) bool {
	switch addr.Port {
	case smtpPortStandard, smtpPortSubmissionTLS, smtpPortSubmission:
	default:
		return false
	}

	ip := addr.IP
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}

	// Block CGNAT range (100.64.0.0/10)
	if cgnat := ip.To4(); cgnat != nil && cgnat[0] == 100 && cgnat[1] >= 64 && cgnat[1] <= 127 {
		return false
	}

	return true
}

func (s *Server) dialMailOutboundTCP(conn net.Conn, target string) {
	remoteAddr, err := net.ResolveTCPAddr("tcp", strings.TrimSpace(target))
	if err != nil || remoteAddr == nil {
		logging.Global().Errorf(logging.CatTCP, "mail outbound dial resolve failed for %q: %v", target, err)
		conn.Close()
		return
	}

	if !isAllowedOutboundSMTPTarget(remoteAddr) && !s.isAllowedProbeOutboundTarget(remoteAddr.String()) {
		logging.Global().Errorf(logging.CatTCP, "mail outbound dial REJECTED: target=%s resolved=%s (invalid port or private/loopback IP)", target, remoteAddr.String())
		conn.Close()
		return
	}

	serverConn, err := (&net.Dialer{Timeout: mailDialTimeout, KeepAlive: tcpKeepAliveInterval}).Dial("tcp", remoteAddr.String())
	if err != nil {
		logging.Global().Errorf(logging.CatTCP, "mail outbound dial failed for %s: %v", remoteAddr.String(), err)
		conn.Close()
		return
	}
	netutil.SetTCPKeepAlive(serverConn, tcpKeepAliveInterval)
	netutil.SetTCPNoDelay(serverConn)
	_ = conn.SetDeadline(time.Time{})
	logging.Global().Infof(logging.CatTCP, "Mail outbound relay connected target=%s", remoteAddr.String())
	go relay.ProxyWithIdleTimeout(serverConn, conn, mailRelayIdleTimeout)
}

func (s *Server) allowProbeOutboundTarget(target string, ttl time.Duration) (string, error) {
	remoteAddr, err := net.ResolveTCPAddr("tcp", strings.TrimSpace(target))
	if err != nil || remoteAddr == nil {
		return "", fmt.Errorf("resolve probe outbound target %q: %w", target, err)
	}
	if ttl <= 0 {
		ttl = probeDefaultTTL
	}
	key := remoteAddr.String()
	now := time.Now()

	s.probeOutboundMu.Lock()
	defer s.probeOutboundMu.Unlock()
	if s.probeOutboundTargets == nil {
		s.probeOutboundTargets = make(map[string]time.Time)
	}
	for existing, expiry := range s.probeOutboundTargets {
		if !expiry.After(now) {
			delete(s.probeOutboundTargets, existing)
		}
	}
	s.probeOutboundTargets[key] = now.Add(ttl)
	return key, nil
}

func (s *Server) revokeProbeOutboundTarget(target string) {
	if strings.TrimSpace(target) == "" {
		return
	}
	s.probeOutboundMu.Lock()
	delete(s.probeOutboundTargets, target)
	s.probeOutboundMu.Unlock()
}

func (s *Server) isAllowedProbeOutboundTarget(target string) bool {
	now := time.Now()
	s.probeOutboundMu.Lock()
	defer s.probeOutboundMu.Unlock()
	if len(s.probeOutboundTargets) == 0 {
		return false
	}
	for existing, expiry := range s.probeOutboundTargets {
		if !expiry.After(now) {
			delete(s.probeOutboundTargets, existing)
		}
	}
	expiresAt, ok := s.probeOutboundTargets[target]
	return ok && expiresAt.After(now)
}

func buildHelloRoutes(cfg ServerConfig, dynamicRoutes map[string]dynamicRouteEntry) map[string]helloRoute {
	effective := effectiveRoutes(cfg, dynamicRoutes)
	routes := make(map[string]helloRoute, len(effective))
	for _, rt := range effective {
		routes[rt.Name] = helloRoute{
			Name:       rt.Name,
			Proto:      rt.Proto,
			PublicAddr: rt.PublicAddr,
			LocalAddr:  rt.LocalAddr,
			Encrypted:  rt.IsEncrypted(),
			Algorithm:  cfg.EncryptionAlgorithm,
		}
	}
	return routes
}

func buildHelloPayload(cfg ServerConfig, dynamicRoutes map[string]dynamicRouteEntry) helloPayload {
	return helloPayload{
		Routes:     buildHelloRoutes(cfg, dynamicRoutes),
		Email:      emailcfg.Normalize(cfg.Email),
		Version:    protocol.ProtocolVersion,
		PublicAddr: strings.TrimSpace(cfg.PublicAddr),
	}
}

func buildHelloRoutesForAgent(cfg ServerConfig, dynamicRoutes map[string]dynamicRouteEntry, agentID string) map[string]helloRoute {
	routes := make(map[string]helloRoute)
	for _, rt := range effectiveRoutes(cfg, dynamicRoutes) {
		if rt.OwnerAgent() != agentID {
			continue
		}
		routes[rt.Name] = helloRoute{
			Name:       rt.Name,
			Proto:      rt.Proto,
			PublicAddr: rt.PublicAddr,
			LocalAddr:  rt.LocalAddr,
			Encrypted:  rt.IsEncrypted(),
			Algorithm:  cfg.EncryptionAlgorithm,
		}
	}
	return routes
}

// buildHelloPayloadForAgent sends agentID its routes; mail config only to the email agent.
func buildHelloPayloadForAgent(cfg ServerConfig, dynamicRoutes map[string]dynamicRouteEntry, agentID string) helloPayload {
	email := emailcfg.Config{}
	if cfg.EmailRouteAgent() == agentID {
		email = emailcfg.Normalize(cfg.Email)
	}
	return helloPayload{
		Routes:     buildHelloRoutesForAgent(cfg, dynamicRoutes, agentID),
		Email:      email,
		Version:    protocol.ProtocolVersion,
		PublicAddr: strings.TrimSpace(cfg.PublicAddr),
	}
}

// buildHelloBytesForAgent marshals under s.mu so dynamicRoutes isn't read after unlock.
func (s *Server) buildHelloBytesForAgent(agentID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.Marshal(buildHelloPayloadForAgent(s.cfg, s.dynamicRoutes, agentID))
}

func (s *Server) buildHelloPacketForAgent(agentID string) (*protocol.Packet, error) {
	b, err := s.buildHelloBytesForAgent(agentID)
	if err != nil {
		return nil, err
	}
	return &protocol.Packet{Type: protocol.TypeHello, Payload: b}, nil
}

// broadcastHello pushes each connected agent its filtered HELLO after a route change.
// Rapid successive mutations are coalesced into a single broadcast.
func (s *Server) broadcastHello() {
	const debounce = 50 * time.Millisecond
	s.helloMu.Lock()
	defer s.helloMu.Unlock()
	if s.helloPending {
		return
	}
	s.helloPending = true
	s.helloTimer = time.AfterFunc(debounce, func() {
		s.helloMu.Lock()
		s.helloPending = false
		s.helloTimer = nil
		s.helloMu.Unlock()
		s.broadcastHelloNow()
	})
}

func (s *Server) broadcastHelloNow() {
	type target struct {
		id   string
		sess *agentSession
	}
	s.sessionsMu.Lock()
	targets := make([]target, 0, len(s.sessions))
	for id, sess := range s.sessions {
		targets = append(targets, target{id: id, sess: sess})
	}
	s.sessionsMu.Unlock()

	for _, t := range targets {
		t.sess.writeMu.Lock()
		b, err := s.buildHelloBytesForAgent(t.id)
		if err != nil {
			t.sess.writeMu.Unlock()
			continue
		}
		pkt := &protocol.Packet{Type: protocol.TypeHello, Payload: b}
		t.sess.conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
		if err := protocol.WritePacket(t.sess.conn, pkt); err != nil {
			logging.Global().Warnf(logging.CatControl, "failed to push hello to agent %q: %v", t.id, err)
		}
		t.sess.conn.SetWriteDeadline(time.Time{})
		t.sess.writeMu.Unlock()
	}
}

func (s *Server) runtimeStats(lastAgentConnectAt, lastAgentDisconnectAt time.Time) *DashboardRuntime {
	s.mu.RLock()
	pendingTCP := len(s.pendingTCP)
	managedDomains := 0
	for _, rt := range s.cfg.Routes {
		if rt.IsEnabled() && rt.IsDomainEnabled() {
			managedDomains++
		}
	}
	cache, _ := s.routeCache.Load().(map[string]routeConfig)
	routeCacheEntries := len(cache)
	s.mu.RUnlock()

	s.sessionsMu.Lock()
	agentSessions := len(s.sessions)
	s.sessionsMu.Unlock()

	managedProxyRoutes := 0
	s.domainProxyCache.Range(func(_, _ any) bool {
		managedProxyRoutes++
		return true
	})

	return &DashboardRuntime{
		PendingTCP:              pendingTCP,
		AgentSessions:           agentSessions,
		ManagedProxyRoutes:      managedProxyRoutes,
		ManagedDomains:          managedDomains,
		RouteCacheEntries:       routeCacheEntries,
		LastAgentConnectUnix:    unixOrZero(lastAgentConnectAt),
		LastAgentDisconnectUnix: unixOrZero(lastAgentDisconnectAt),
	}
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func isEmailRoute(name string) bool {
	switch name {
	case internalEmailInboundRouteName,
		internalEmailSubmissionRouteName,
		internalEmailSubmissionTLSRouteName,
		internalEmailIMAPRouteName,
		internalEmailIMAPTLSRouteName:
		return true
	}
	return false
}

func writeMailRouteUnavailable(conn net.Conn, routeName string) {
	if conn == nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeDeadlineShort))
	switch routeName {
	case internalEmailSubmissionRouteName, internalEmailInboundRouteName:
		_, _ = io.WriteString(conn, "421 4.3.0 HostIt mail backend unavailable\r\n")
	case internalEmailIMAPRouteName:
		_, _ = io.WriteString(conn, "* BYE HostIt mail backend unavailable\r\n")
	case internalEmailSubmissionTLSRouteName, internalEmailIMAPTLSRouteName:
		// Implicit TLS: close silently. Writing plaintext would trigger
		// "first record does not look like a TLS handshake" on the client.
	}
	_ = conn.SetWriteDeadline(time.Time{})
}

func (s *Server) SetRouteEnabled(name string, enabled bool) bool {
	s.mu.Lock()
	for i, rt := range s.cfg.Routes {
		if rt.Name == name {
			val := enabled
			s.cfg.Routes[i].Enabled = &val
			s.mu.Unlock()

			s.updateRouteCache()
			s.broadcastHello()
			return true
		}
	}
	if dr, ok := s.dynamicRoutes[name]; ok {
		val := enabled
		dr.Route.Enabled = &val
		s.dynamicRoutes[name] = dr
		s.mu.Unlock()

		s.updateRouteCache()
		s.broadcastHello()
		return true
	}
	s.mu.Unlock()
	return false
}

func (s *Server) GetRouteEnabled(name string) bool {
	rc, ok := s.getRouteConfig(name)
	return ok && rc.enabled
}

func (s *Server) ListApps(ctx context.Context) ([]appstore.Application, error) {
	if s.appStore == nil {
		return nil, nil
	}
	return s.appStore.ListApplications(ctx)
}

func (s *Server) SetAppEnabled(label string, enabled bool) bool {
	if s.stopping.Load() {
		return false
	}
	if s.appStore == nil {
		return false
	}
	if err := s.appStore.SetApplicationEnabled(context.Background(), label, enabled); err != nil {
		return false
	}

	// Mutate under lock, but do NOT hold it across net.Listen or hello push.
	s.mu.Lock()
	apps, err := s.appStore.ListApplications(context.Background())
	if err != nil {
		s.mu.Unlock()
		return true
	}
	type listenerNeed struct {
		name  string
		addr  string
		proto string
	}
	var tcpNeeds, udpNeeds []listenerNeed
	for _, app := range apps {
		for _, route := range app.Routes {
			if dr, ok := s.dynamicRoutes[route.RouteName]; ok {
				val := app.Enabled && route.Enabled
				dr.Route.Enabled = &val
				s.dynamicRoutes[route.RouteName] = dr
				if ln, hasLn := s.publicTCP[route.RouteName]; hasLn && !val {
					ln.Close()
					delete(s.publicTCP, route.RouteName)
				}
				if conn, hasConn := s.publicUDP[route.RouteName]; hasConn && !val {
					conn.Close()
					delete(s.publicUDP, route.RouteName)
				}
				if val {
					if _, hasLn := s.publicTCP[route.RouteName]; !hasLn && (dr.Route.Proto == routeProtoTCP || dr.Route.Proto == routeProtoBoth) && strings.TrimSpace(dr.Route.PublicAddr) != "" {
						tcpNeeds = append(tcpNeeds, listenerNeed{name: route.RouteName, addr: dr.Route.PublicAddr, proto: dr.Route.Proto})
					}
					if _, hasConn := s.publicUDP[route.RouteName]; !hasConn && (dr.Route.Proto == routeProtoUDP || dr.Route.Proto == routeProtoBoth) && strings.TrimSpace(dr.Route.PublicAddr) != "" {
						udpNeeds = append(udpNeeds, listenerNeed{name: route.RouteName, addr: dr.Route.PublicAddr, proto: dr.Route.Proto})
					}
				}
			}
		}
	}
	s.updateRouteCacheLocked()
	s.mu.Unlock()

	// Open listeners after unlock to avoid blocking public accepts.
	for _, need := range tcpNeeds {
		ln, err := net.Listen("tcp", need.addr)
		if err == nil {
			s.mu.Lock()
			if s.ctx != nil && !s.stopping.Load() {
				s.publicTCP[need.name] = ln
				s.wg.Add(1)
				go s.acceptPublicTCP(ln, need.name)
			} else {
				ln.Close()
			}
			s.mu.Unlock()
		}
	}
	for _, need := range udpNeeds {
		addr, err := net.ResolveUDPAddr("udp", need.addr)
		if err == nil {
			conn, err := net.ListenUDP("udp", addr)
			if err == nil {
				configureRouteUDPSocket(conn, need.name)
				s.mu.Lock()
				if s.ctx != nil && !s.stopping.Load() {
					s.publicUDP[need.name] = conn
					s.publishPublicUDPLocked()
					s.wg.Add(1)
					go s.acceptPublicUDP(conn, need.name)
				} else {
					conn.Close()
				}
				s.mu.Unlock()
			}
		}
	}

	s.broadcastHello()
	return true
}

func (s *Server) DeleteApp(label string) bool {
	if s.appStore == nil {
		return false
	}
	app, err := s.appStore.GetApplication(context.Background(), label)
	if err != nil || app == nil {
		return false
	}
	s.mu.Lock()
	for _, route := range app.Routes {
		if ln, ok := s.publicTCP[route.RouteName]; ok {
			ln.Close()
			delete(s.publicTCP, route.RouteName)
		}
		if conn, ok := s.publicUDP[route.RouteName]; ok {
			conn.Close()
			delete(s.publicUDP, route.RouteName)
		}
		delete(s.dynamicRoutes, route.RouteName)
		delete(s.derivedKeys, route.RouteName)
	}
	s.updateRouteCacheLocked()
	s.mu.Unlock()

	if err := s.appStore.DeleteApplication(context.Background(), label); err != nil {
		return false
	}

	s.broadcastHello()
	return true
}

func boolPtr(b bool) *bool {
	return &b
}

func (s *Server) handleRouteRequest(conn net.Conn, session *agentSession, payload []byte) {
	var req apitypes.RouteRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to parse route request: %v", err)
		return
	}

	s.mu.Lock()
	resp := s.processRouteRequestLocked(req, session.agentID)
	s.mu.Unlock()

	// Persist after unlock so slow disk does not freeze the server.
	// pending_domain with a public address still installs (or will install) a
	// route worth tracking; pure domain-query responses have no PublicAddr.
	if resp.Status != "failed" && s.appStore != nil {
		if resp.Status != "pending_domain" || strings.TrimSpace(resp.PublicAddr) != "" {
			s.persistRouteToStore(context.Background(), req, resp, session.agentID)
		}
	}

	respPayload, err := json.Marshal(resp)
	if err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to marshal route response: %v", err)
		return
	}

	session.writeMu.Lock()
	conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRouteResponse, Payload: respPayload}); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to send route response: %v", err)
	}
	conn.SetWriteDeadline(time.Time{})
	session.writeMu.Unlock()

	s.broadcastHello()
}

func (s *Server) persistRouteToStore(ctx context.Context, req apitypes.RouteRequest, resp apitypes.RouteResponse, owner string) {
	label := strings.TrimSpace(req.Name)
	if req.Source != "api" || label == "" {
		label = strings.TrimSpace(resp.Name)
	}
	rt := appstore.AppRoute{
		RouteName:     resp.Name,
		Proto:         resp.Proto,
		PublicAddr:    resp.PublicAddr,
		LocalAddr:     resp.LocalAddr,
		AgentID:       owner,
		Encrypted:     req.Encrypted,
		Domain:        resp.Domain,
		DomainEnabled: resp.Domain != "" && resp.Status != "failed",
		Enabled:       true,
	}
	if err := s.upsertAppRoute(ctx, label, rt); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to persist route %s: %v", resp.Name, err)
	}
}

// upsertAppRoute inserts a new application route or updates the existing row in
// place. Re-registration must not fail the registry write on UNIQUE(route_name).
func (s *Server) upsertAppRoute(ctx context.Context, appLabel string, rt appstore.AppRoute) error {
	if s.appStore == nil {
		return nil
	}
	appLabel = strings.TrimSpace(appLabel)
	if appLabel == "" {
		appLabel = strings.TrimSpace(rt.RouteName)
	}
	if appLabel == "" || strings.TrimSpace(rt.RouteName) == "" {
		return fmt.Errorf("application label and route name are required")
	}

	existing, err := s.appStore.GetRouteByRouteName(ctx, rt.RouteName)
	if err != nil {
		return err
	}
	if existing != nil {
		return s.appStore.UpdateRoute(ctx, rt)
	}

	app, err := s.appStore.GetApplication(ctx, appLabel)
	if err != nil {
		return err
	}
	if app == nil {
		app, err = s.appStore.CreateApplication(ctx, appLabel, "")
		if err != nil {
			if !appstore.IsUniqueConstraint(err) {
				return err
			}
			app, err = s.appStore.GetApplication(ctx, appLabel)
			if err != nil {
				return err
			}
			if app == nil {
				return fmt.Errorf("application %q missing after unique conflict", appLabel)
			}
		}
	}
	if _, err := s.appStore.AddRoute(ctx, app.ID, rt); err != nil {
		if appstore.IsUniqueConstraint(err) {
			return s.appStore.UpdateRoute(ctx, rt)
		}
		return err
	}
	return nil
}

func (s *Server) processRouteRequestLocked(req apitypes.RouteRequest, owner string) apitypes.RouteResponse {
	if s.stopping.Load() {
		return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "server is stopping"}
	}
	if strings.TrimSpace(owner) == "" {
		owner = protocol.DefaultAgentID
	}
	if req.Name == "" {
		return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Error: "name is required"}
	}
	if err := validateRouteName(req.Name); err != nil {
		return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: err.Error()}
	}

	switch strings.ToLower(strings.TrimSpace(req.Proto)) {
	case "tcp", "udp", "both":
	default:
		return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "invalid proto"}
	}
	allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	routeNames := make(map[string]bool)
	for _, rt := range allRoutes {
		routeNames[rt.Name] = true
	}
	if routeNames[req.Name] {
		return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "route name already exists"}
	}

	domain := strings.TrimSpace(req.Domain)
	var availableDomains []apitypes.DomainOption

	if domain == "_query" {
		availableDomains = s.buildDomainOptionsLocked()
		return apitypes.RouteResponse{RequestID: req.RequestID, Status: "pending_domain", Name: req.Name, Domain: normalizeHostname(s.cfg.DomainBase), AvailableDomains: availableDomains}
	}

	var publicAddr string
	if req.PublicPort > 0 {
		publicAddr = fmt.Sprintf(":%d", req.PublicPort)
		for _, rt := range allRoutes {
			if rt.PublicAddr != "" && publicTCPAddrsConflict(rt.PublicAddr, publicAddr) {
				return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("public port %d conflicts with route %q", req.PublicPort, rt.Name)}
			}
		}
	} else {
		assigned := s.assignPortLocked(allRoutes)
		if assigned == 0 {
			return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "no available ports in dynamic range"}
		}
		publicAddr = fmt.Sprintf(":%d", assigned)
	}

	if s.cfg.MaxDynamicRoutesPerAgent > 0 {
		ownerCount := 0
		for _, dr := range s.dynamicRoutes {
			if dr.Route.OwnerAgent() == owner {
				ownerCount++
			}
		}
		if ownerCount >= s.cfg.MaxDynamicRoutesPerAgent {
			return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "max dynamic routes reached"}
		}
	}

	if domain == "auto" || (domain != "" && s.cfg.DomainManagerEnabled) {
		availableDomains = s.buildDomainOptionsLocked()
		if domain == "auto" {
			suggested := req.Name + "." + normalizeHostname(s.cfg.DomainBase)
			suggestedAvail := true
			for _, rt := range allRoutes {
				if rt.IsDomainEnabled() && normalizeHostname(rt.Domain) == normalizeHostname(suggested) {
					suggestedAvail = false
					break
				}
			}
			if suggestedAvail {
				domain = suggested
			}
			if domain == "auto" {
				return apitypes.RouteResponse{RequestID: req.RequestID, Status: "pending_domain", Name: req.Name, PublicAddr: publicAddr, AvailableDomains: availableDomains}
			}
		}
		if domain != "" && s.cfg.DomainManagerEnabled {
			normalized := normalizeHostname(domain)
			if err := validateHostname(normalized); err != nil {
				return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "invalid domain: " + err.Error()}
			}
			if base := normalizeHostname(s.cfg.DomainBase); base != "" && !hostnameWithinBase(normalized, base) {
				return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("domain %q must be within base domain %q", normalized, s.cfg.DomainBase)}
			}
			domainConflicts := false
			for _, rt := range allRoutes {
				if rt.IsDomainEnabled() && normalizeHostname(rt.Domain) == normalized {
					domainConflicts = true
					break
				}
			}
			if domainConflicts {
				if domain == "auto" {
					return apitypes.RouteResponse{RequestID: req.RequestID, Status: "pending_domain", Name: req.Name, PublicAddr: publicAddr, AvailableDomains: availableDomains}
				}
				return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "domain already in use"}
			}
			if strings.ToLower(strings.TrimSpace(req.Proto)) == "udp" {
				return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "domain routing requires tcp or both"}
			}
		}
	}

	domainEnabled := domain != "" && s.cfg.DomainManagerEnabled
	enc := req.Encrypted
	rt := RouteConfig{
		Name:          req.Name,
		Proto:         strings.ToLower(strings.TrimSpace(req.Proto)),
		PublicAddr:    publicAddr,
		LocalAddr:     strings.TrimSpace(req.LocalAddr),
		Agent:         owner,
		Enabled:       boolPtr(true),
		Encrypted:     &enc,
		Domain:        domain,
		DomainEnabled: &domainEnabled,
	}

	s.dynamicRoutes[req.Name] = dynamicRouteEntry{
		Route:     rt,
		CreatedAt: time.Now(),
		Source:    req.Source,
	}

	if rt.IsEncrypted() {
		if key := s.encryptionBaseKey(); key != nil {
			s.derivedKeys[rt.Name] = key
		}
	}

	if strings.TrimSpace(rt.PublicAddr) != "" && (rt.Proto == routeProtoTCP || rt.Proto == routeProtoBoth) {
		ln, err := net.Listen("tcp", rt.PublicAddr)
		if err != nil {
			delete(s.dynamicRoutes, req.Name)
			return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("failed to listen on %s: %v", rt.PublicAddr, err)}
		}
		s.publicTCP[rt.Name] = ln
		if s.ctx != nil {
			s.wg.Add(1)
			go s.acceptPublicTCP(ln, rt.Name)
		}
	}
	if strings.TrimSpace(rt.PublicAddr) != "" && (rt.Proto == routeProtoUDP || rt.Proto == routeProtoBoth) {
		addr, err := net.ResolveUDPAddr("udp", rt.PublicAddr)
		if err != nil {
			s.rollbackDynamicRouteLocked(req.Name)
			return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("failed to resolve udp %s: %v", rt.PublicAddr, err)}
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			s.rollbackDynamicRouteLocked(req.Name)
			return apitypes.RouteResponse{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("failed to listen udp on %s: %v", rt.PublicAddr, err)}
		}
		configureRouteUDPSocket(conn, rt.Name)
		s.publicUDP[rt.Name] = conn
		if s.ctx != nil {
			s.wg.Add(1)
			go s.acceptPublicUDP(conn, rt.Name)
		}
	}

	s.updateRouteCacheLocked()

	status := "active"
	if domain == "auto" && len(availableDomains) > 0 {
		status = "pending_domain"
	}

	return apitypes.RouteResponse{
		RequestID:        req.RequestID,
		Status:           status,
		Name:             req.Name,
		Proto:            rt.Proto,
		PublicAddr:       rt.PublicAddr,
		LocalAddr:        rt.LocalAddr,
		Domain:           domain,
		AvailableDomains: availableDomains,
	}
}

// rollbackDynamicRouteLocked undoes a partially applied dynamic route create
// (e.g. TCP listen succeeded but UDP listen failed).
func (s *Server) rollbackDynamicRouteLocked(name string) {
	if ln, exists := s.publicTCP[name]; exists {
		ln.Close()
		delete(s.publicTCP, name)
	}
	if conn, exists := s.publicUDP[name]; exists {
		conn.Close()
		delete(s.publicUDP, name)
	}
	delete(s.dynamicRoutes, name)
	delete(s.derivedKeys, name)
	s.connSemaphores.Delete(name)
	s.domainProxyCache.Delete(name)
	if s.dash != nil {
		s.dash.removeRoute(name)
	}
}

func (s *Server) assignPortLocked(allRoutes []RouteConfig) int {
	used := make(map[int]bool)
	for _, rt := range allRoutes {
		if strings.TrimSpace(rt.PublicAddr) != "" {
			if addr, err := net.ResolveTCPAddr("tcp", rt.PublicAddr); err == nil && addr != nil {
				used[addr.Port] = true
			}
		}
	}
	for port := s.dynamicPortLow; port <= s.dynamicPortHigh; port++ {
		if !used[port] {
			return port
		}
	}
	return 0
}

func (s *Server) buildDomainOptionsLocked() []apitypes.DomainOption {
	if !s.cfg.DomainManagerEnabled {
		return nil
	}
	base := normalizeHostname(s.cfg.DomainBase)
	if base == "" {
		return nil
	}
	allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	usedDomains := make(map[string]string)
	for _, rt := range allRoutes {
		if rt.IsDomainEnabled() {
			h := normalizeHostname(rt.Domain)
			if h != "" {
				usedDomains[h] = rt.Name
			}
		}
	}
	var options []apitypes.DomainOption
	for name := range s.dynamicRoutes {
		suggested := name + "." + base
		_, used := usedDomains[suggested]
		options = append(options, apitypes.DomainOption{
			Host:      suggested,
			Available: !used,
		})
		if used {
			options[len(options)-1].UsedBy = usedDomains[suggested]
			options[len(options)-1].Reason = "already in use"
		}
	}
	return options
}

func (s *Server) handleRouteConfirm(conn net.Conn, session *agentSession, payload []byte) {
	var confirm apitypes.RouteConfirm
	if err := json.Unmarshal(payload, &confirm); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to parse route confirm: %v", err)
		return
	}

	s.mu.Lock()
	ack := s.processRouteConfirmLocked(confirm, session.agentID)
	var drProto, drLocalAddr, drDomain, drAgent string
	var drEncrypted, drEnabled bool
	if dr, ok := s.dynamicRoutes[confirm.Name]; ok {
		drProto = dr.Route.Proto
		drLocalAddr = dr.Route.LocalAddr
		drEncrypted = dr.Route.IsEncrypted()
		drEnabled = dr.Route.IsEnabled()
		drDomain = dr.Route.Domain
		drAgent = dr.Route.OwnerAgent()
	}
	s.mu.Unlock()

	// Persist domain confirm after unlock. Create the registry row when the
	// initial request was pending_domain and never inserted one.
	if ack.Status != "failed" && s.appStore != nil {
		label := confirm.Name
		err := s.upsertAppRoute(context.Background(), label, appstore.AppRoute{
			RouteName:     confirm.Name,
			Proto:         drProto,
			PublicAddr:    ack.PublicAddr,
			LocalAddr:     drLocalAddr,
			AgentID:       drAgent,
			Encrypted:     drEncrypted,
			Domain:        drDomain,
			DomainEnabled: true,
			Enabled:       drEnabled,
		})
		if err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to persist confirmed route %s: %v", confirm.Name, err)
		}
	}

	ackPayload, err := json.Marshal(ack)
	if err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to marshal route ack: %v", err)
		return
	}

	session.writeMu.Lock()
	conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRouteAck, Payload: ackPayload}); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to send route ack: %v", err)
	}
	conn.SetWriteDeadline(time.Time{})
	session.writeMu.Unlock()

	s.broadcastHello()
}

func (s *Server) processRouteConfirmLocked(confirm apitypes.RouteConfirm, owner string) apitypes.RouteAck {
	dr, ok := s.dynamicRoutes[confirm.Name]
	if !ok {
		return apitypes.RouteAck{RequestID: confirm.RequestID, Status: "failed", Name: confirm.Name, Error: "dynamic route not found"}
	}
	if owner == "" {
		owner = protocol.DefaultAgentID
	}
	if dr.Route.OwnerAgent() != owner {
		return apitypes.RouteAck{RequestID: confirm.RequestID, Status: "failed", Name: confirm.Name, Error: "route owned by another agent"}
	}

	domain := normalizeHostname(confirm.Domain)
	if err := validateHostname(domain); err != nil {
		return apitypes.RouteAck{RequestID: confirm.RequestID, Status: "failed", Name: confirm.Name, Error: "invalid domain: " + err.Error()}
	}
	if s.cfg.DomainManagerEnabled {
		if base := normalizeHostname(s.cfg.DomainBase); base != "" && !hostnameWithinBase(domain, base) {
			return apitypes.RouteAck{RequestID: confirm.RequestID, Status: "failed", Name: confirm.Name, Error: fmt.Sprintf("domain %q must be within base domain %q", domain, s.cfg.DomainBase)}
		}
	}

	allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	for _, rt := range allRoutes {
		if rt.Name != confirm.Name && rt.IsDomainEnabled() && normalizeHostname(rt.Domain) == domain {
			return apitypes.RouteAck{RequestID: confirm.RequestID, Status: "failed", Name: confirm.Name, Domain: domain, Error: "domain already taken by route " + rt.Name}
		}
	}

	dr.Route.Domain = domain
	domainEnabled := true
	dr.Route.DomainEnabled = &domainEnabled
	s.dynamicRoutes[confirm.Name] = dr

	s.updateRouteCacheLocked()

	return apitypes.RouteAck{
		RequestID:  confirm.RequestID,
		Status:     "active",
		Name:       confirm.Name,
		Domain:     domain,
		PublicAddr: dr.Route.PublicAddr,
	}
}

func (s *Server) handleRouteRemove(conn net.Conn, session *agentSession, payload []byte) {
	var remove apitypes.RouteRemove
	if err := json.Unmarshal(payload, &remove); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to parse route remove: %v", err)
		return
	}

	s.mu.Lock()
	ack := s.processRouteRemoveLocked(remove, session.agentID)
	s.mu.Unlock()

	if ack.OK && s.appStore != nil {
		if err := s.appStore.RemoveRoute(context.Background(), remove.Name); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to remove persisted route %s: %v", remove.Name, err)
		}
	}

	ackPayload, err := json.Marshal(ack)
	if err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to marshal route remove ack: %v", err)
		return
	}

	session.writeMu.Lock()
	conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRouteRemoveAck, Payload: ackPayload}); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to send route remove ack: %v", err)
	}
	conn.SetWriteDeadline(time.Time{})
	session.writeMu.Unlock()

	s.broadcastHello()
}

func (s *Server) processRouteRemoveLocked(remove apitypes.RouteRemove, owner string) apitypes.RouteRemoveAck {
	dr, ok := s.dynamicRoutes[remove.Name]
	if !ok {
		return apitypes.RouteRemoveAck{Name: remove.Name, Error: "dynamic route not found"}
	}
	if owner == "" {
		owner = protocol.DefaultAgentID
	}
	if dr.Route.OwnerAgent() != owner {
		return apitypes.RouteRemoveAck{Name: remove.Name, Error: "route owned by another agent"}
	}

	if ln, exists := s.publicTCP[remove.Name]; exists {
		ln.Close()
		delete(s.publicTCP, remove.Name)
	}
	if conn, exists := s.publicUDP[remove.Name]; exists {
		conn.Close()
		delete(s.publicUDP, remove.Name)
	}

	delete(s.dynamicRoutes, remove.Name)
	delete(s.derivedKeys, remove.Name)
	s.connSemaphores.Delete(remove.Name)
	s.domainProxyCache.Delete(remove.Name)
	if s.dash != nil {
		s.dash.removeRoute(remove.Name)
	}

	s.updateRouteCacheLocked()

	return apitypes.RouteRemoveAck{Name: remove.Name, OK: true}
}

func (s *Server) handleRouteUpdate(conn net.Conn, session *agentSession, payload []byte) {
	var req apitypes.RouteUpdate
	if err := json.Unmarshal(payload, &req); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to parse route update: %v", err)
		return
	}

	s.mu.Lock()
	ack := s.processRouteUpdateLocked(req, session.agentID)
	var updProto, updPublicAddr, updLocalAddr, updDomain string
	var updEncrypted, updDomainEnabled, updEnabled bool
	if dr, ok := s.dynamicRoutes[req.Name]; ok {
		updProto = dr.Route.Proto
		updPublicAddr = dr.Route.PublicAddr
		updLocalAddr = dr.Route.LocalAddr
		updEncrypted = dr.Route.IsEncrypted()
		updDomain = dr.Route.Domain
		updDomainEnabled = dr.Route.IsDomainEnabled()
		updEnabled = dr.Route.IsEnabled()
	}
	s.mu.Unlock()

	if ack.Status != "failed" && s.appStore != nil {
		ctx := context.Background()
		agentID := ""
		if existing, err := s.appStore.GetRouteByRouteName(ctx, req.Name); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to load persisted route %s for update: %v", req.Name, err)
		} else if existing != nil {
			agentID = existing.AgentID
		}
		if agentID == "" {
			agentID = session.agentID
		}
		if err := s.upsertAppRoute(ctx, req.Name, appstore.AppRoute{
			RouteName:     req.Name,
			Proto:         updProto,
			PublicAddr:    updPublicAddr,
			LocalAddr:     updLocalAddr,
			AgentID:       agentID,
			Encrypted:     updEncrypted,
			Domain:        updDomain,
			DomainEnabled: updDomainEnabled,
			Enabled:       updEnabled,
		}); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to persist route update %s: %v", req.Name, err)
		}
	}

	ackPayload, err := json.Marshal(ack)
	if err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to marshal route update ack: %v", err)
		return
	}

	session.writeMu.Lock()
	conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeRouteUpdateAck, Payload: ackPayload}); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to send route update ack: %v", err)
	}
	conn.SetWriteDeadline(time.Time{})
	session.writeMu.Unlock()

	s.broadcastHello()
}

func (s *Server) processRouteUpdateLocked(req apitypes.RouteUpdate, owner string) apitypes.RouteUpdateAck {
	if s.stopping.Load() {
		return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "server is stopping"}
	}
	dr, ok := s.dynamicRoutes[req.Name]
	if !ok {
		return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "dynamic route not found"}
	}
	if owner == "" {
		owner = protocol.DefaultAgentID
	}
	if dr.Route.OwnerAgent() != owner {
		return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "route owned by another agent"}
	}
	if req.LocalAddr != "" {
		dr.Route.LocalAddr = strings.TrimSpace(req.LocalAddr)
	}

	if req.PublicPort > 0 {
		newAddr := fmt.Sprintf(":%d", req.PublicPort)
		allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
		for _, rt := range allRoutes {
			if rt.Name != req.Name && rt.PublicAddr != "" && publicTCPAddrsConflict(rt.PublicAddr, newAddr) {
				return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("public port %d conflicts with route %q", req.PublicPort, rt.Name)}
			}
		}
		oldAddr := dr.Route.PublicAddr
		// Already bound to this address: keep existing listeners.
		if strings.TrimSpace(oldAddr) != "" && publicTCPAddrsConflict(oldAddr, newAddr) {
			dr.Route.PublicAddr = newAddr
		} else {
			// Bind new listeners before closing old ones so a partial failure
			// (e.g. TCP ok, UDP fail on "both") leaves the route unchanged.
			needTCP := dr.Route.Proto == routeProtoTCP || dr.Route.Proto == routeProtoBoth
			needUDP := dr.Route.Proto == routeProtoUDP || dr.Route.Proto == routeProtoBoth
			var newTCP net.Listener
			var newUDP *net.UDPConn
			if needTCP {
				ln, err := net.Listen("tcp", newAddr)
				if err != nil {
					return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("failed to listen on %s: %v", newAddr, err)}
				}
				newTCP = ln
			}
			if needUDP {
				addr, err := net.ResolveUDPAddr("udp", newAddr)
				if err != nil {
					if newTCP != nil {
						newTCP.Close()
					}
					return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("failed to resolve udp %s: %v", newAddr, err)}
				}
				conn, err := net.ListenUDP("udp", addr)
				if err != nil {
					if newTCP != nil {
						newTCP.Close()
					}
					return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("failed to listen udp on %s: %v", newAddr, err)}
				}
				configureRouteUDPSocket(conn, dr.Route.Name)
				newUDP = conn
			}

			if oldLn, ok := s.publicTCP[req.Name]; ok {
				oldLn.Close()
				delete(s.publicTCP, req.Name)
			}
			if oldConn, ok := s.publicUDP[req.Name]; ok {
				oldConn.Close()
				delete(s.publicUDP, req.Name)
			}
			dr.Route.PublicAddr = newAddr
			if newTCP != nil {
				s.publicTCP[req.Name] = newTCP
				s.wg.Add(1)
				go s.acceptPublicTCP(newTCP, req.Name)
			}
			if newUDP != nil {
				s.publicUDP[req.Name] = newUDP
				s.wg.Add(1)
				go s.acceptPublicUDP(newUDP, req.Name)
			}
		}
	}

	if req.Domain != "" {
		normalized := normalizeHostname(req.Domain)
		if err := validateHostname(normalized); err != nil {
			return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "invalid domain: " + err.Error()}
		}
		if base := normalizeHostname(s.cfg.DomainBase); base != "" && !hostnameWithinBase(normalized, base) {
			return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("domain %q must be within base domain %q", normalized, s.cfg.DomainBase)}
		}
		allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
		for _, rt := range allRoutes {
			if rt.Name != req.Name && rt.IsDomainEnabled() && normalizeHostname(rt.Domain) == normalized {
				return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "domain already in use by route " + rt.Name}
			}
		}
		dr.Route.Domain = normalized
		domainEnabled := true
		dr.Route.DomainEnabled = &domainEnabled
	}

	if req.Encrypted != nil {
		dr.Route.Encrypted = req.Encrypted
		if *req.Encrypted {
			if key := s.encryptionBaseKey(); key != nil {
				s.derivedKeys[req.Name] = key
			}
		} else {
			delete(s.derivedKeys, req.Name)
		}
	}

	s.dynamicRoutes[req.Name] = dr
	s.updateRouteCacheLocked()

	return apitypes.RouteUpdateAck{
		RequestID: req.RequestID,
		Status:    "updated",
		Name:      req.Name,
	}
}

func (s *Server) RouteStats(routeName string) *apitypes.RouteStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	var found *RouteConfig
	for _, rt := range allRoutes {
		if rt.Name == routeName {
			found = &rt
			break
		}
	}
	if found == nil {
		return nil
	}

	source := "config"
	if _, ok := s.dynamicRoutes[routeName]; ok {
		source = "dynamic"
	}

	owner := found.OwnerAgent()
	_, ownerConnected := s.sessionForAgent(owner)
	return &apitypes.RouteStats{
		Name:       found.Name,
		Proto:      found.Proto,
		PublicAddr: found.PublicAddr,
		LocalAddr:  found.LocalAddr,
		Domain:     found.Domain,
		Agent:      owner,
		Connected:  ownerConnected,
		Source:     source,
	}
}

func (s *Server) AllRouteStats() []apitypes.RouteStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	connected := make(map[string]bool)
	for _, id := range s.connectedAgentIDs() {
		connected[id] = true
	}
	stats := make([]apitypes.RouteStats, 0, len(allRoutes))
	for _, rt := range allRoutes {
		source := "config"
		if _, ok := s.dynamicRoutes[rt.Name]; ok {
			source = "dynamic"
		}
		owner := rt.OwnerAgent()
		stats = append(stats, apitypes.RouteStats{
			Name:       rt.Name,
			Proto:      rt.Proto,
			PublicAddr: rt.PublicAddr,
			LocalAddr:  rt.LocalAddr,
			Domain:     rt.Domain,
			Agent:      owner,
			Connected:  connected[owner],
			Source:     source,
		})
	}
	return stats
}

func (s *Server) RunAgentNettest(ctx context.Context, req AgentNettestRequest) (AgentNettestResult, error) {
	session, ok := s.targetSession(req.AgentID)
	if !ok {
		return AgentNettestResult{}, fmt.Errorf("agent not connected")
	}
	s.mu.Lock()
	if s.pongCh != nil {
		s.mu.Unlock()
		return AgentNettestResult{}, fmt.Errorf("test already in progress")
	}
	pongCh := make(chan []byte, 1000)
	s.pongCh = pongCh
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.pongCh = nil
		s.mu.Unlock()
	}()

	var res AgentNettestResult

	latencyCount := 20
	var (
		minRTT    time.Duration
		maxRTT    time.Duration
		sumRTT    time.Duration
		sumJitter time.Duration
		lastRTT   time.Duration
		latRecv   int
	)

	for i := 0; i < latencyCount; i++ {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		payload := make([]byte, 8)
		binary.BigEndian.PutUint64(payload, uint64(i))
		pkt := &protocol.Packet{Type: protocol.TypePing, Payload: payload}

		sendStart := time.Now()
		session.writeMu.Lock()
		session.conn.SetWriteDeadline(time.Now().Add(writeDeadlineShort))
		err := protocol.WritePacket(session.conn, pkt)
		session.writeMu.Unlock()
		if err != nil {
			continue
		}

		timeout := time.After(nettestTimeout)
	waitLoop:
		for {
			select {
			case <-ctx.Done():
				break waitLoop
			case <-timeout:
				break waitLoop
			case reply := <-pongCh:
				if len(reply) >= 8 {
					seq := binary.BigEndian.Uint64(reply[:8])
					if seq == uint64(i) {
						rtt := time.Since(sendStart)
						latRecv++
						if latRecv == 1 || rtt < minRTT {
							minRTT = rtt
						}
						if rtt > maxRTT {
							maxRTT = rtt
						}
						sumRTT += rtt
						if latRecv > 1 {
							jitter := rtt - lastRTT
							if jitter < 0 {
								jitter = -jitter
							}
							sumJitter += jitter
						}
						lastRTT = rtt
						break waitLoop
					}
				}
			}
		}
	}

	if latRecv > 0 {
		res.MinLatencyMs = float64(minRTT.Microseconds()) / 1000.0
		res.MaxLatencyMs = float64(maxRTT.Microseconds()) / 1000.0
		res.AvgLatencyMs = float64((sumRTT / time.Duration(latRecv)).Microseconds()) / 1000.0
		if latRecv > 1 {
			res.JitterMs = float64((sumJitter / time.Duration(latRecv-1)).Microseconds()) / 1000.0
		}
	}

	bwCount := 100
	bwPayloadBytes := 64000
	var bwSent int32
	var bwRecv int
	var bytesSent int64
	var bytesRecv int64

	bwStart := time.Now()
	sendDone := make(chan struct{})

	go func() {
		defer close(sendDone)
		session.writeMu.Lock()
		session.conn.SetWriteDeadline(time.Now().Add(bwTestTimeout))
		session.writeMu.Unlock()
		for i := 0; i < bwCount; i++ {
			if ctx.Err() != nil {
				break
			}
			payload := make([]byte, bwPayloadBytes)
			binary.BigEndian.PutUint64(payload, uint64(1000+i))
			pkt := &protocol.Packet{Type: protocol.TypePing, Payload: payload}

			session.writeMu.Lock()
			if err := protocol.WritePacket(session.conn, pkt); err != nil {
				session.writeMu.Unlock()
				break
			}
			session.writeMu.Unlock()
			bwSent++
			bytesSent += int64(bwPayloadBytes)
		}
	}()

	timeout := time.After(bwTestTimeout)
bwWaitLoop:
	for bwRecv < bwCount {
		select {
		case <-ctx.Done():
			break bwWaitLoop
		case <-timeout:
			break bwWaitLoop
		case reply := <-pongCh:
			if len(reply) >= 8 {
				seq := binary.BigEndian.Uint64(reply[:8])
				if seq >= 1000 && seq < uint64(1000+bwCount) {
					bwRecv++
					bytesRecv += int64(len(reply))
				}
			}
		}
	}

	<-sendDone
	bwDuration := time.Since(bwStart)

	res.SentPackets = latencyCount + int(bwSent)
	res.LostPackets = (latencyCount - latRecv) + (int(bwSent) - bwRecv)
	res.DurationMs = float64(bwDuration.Milliseconds())

	if res.SentPackets > 0 {
		res.LossPercent = float64(res.LostPackets) / float64(res.SentPackets) * 100
	}
	if bwDuration > 0 {
		res.UploadMbps = float64(bytesSent*8) / bwDuration.Seconds() / 1e6
		res.DownloadMbps = float64(bytesRecv*8) / bwDuration.Seconds() / 1e6
	}

	return res, nil
}

func (s *Server) RunAgentEmailProbe(ctx context.Context, req protocol.EmailProbeRequest) (protocol.EmailProbeResult, error) {
	s.mu.RLock()
	emailAgent := s.cfg.EmailRouteAgent()
	s.mu.RUnlock()
	session, ok := s.sessionForAgent(emailAgent)
	if !ok {
		return protocol.EmailProbeResult{}, fmt.Errorf("email agent %q not connected", emailAgent)
	}
	s.mu.Lock()
	if s.emailProbeCh != nil {
		s.mu.Unlock()
		return protocol.EmailProbeResult{}, fmt.Errorf("email probe already in progress")
	}
	probeCh := make(chan []byte, 1)
	s.emailProbeCh = probeCh
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.emailProbeCh = nil
		s.mu.Unlock()
	}()

	if strings.TrimSpace(req.OutboundTarget) != "" {
		allowedTarget, err := s.allowProbeOutboundTarget(req.OutboundTarget, emailProbeAllowTTL)
		if err != nil {
			return protocol.EmailProbeResult{}, err
		}
		defer s.revokeProbeOutboundTarget(allowedTarget)
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return protocol.EmailProbeResult{}, err
	}
	pkt := &protocol.Packet{Type: protocol.TypeEmailProbeRequest, Payload: payload}

	session.writeMu.Lock()
	session.conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
	err = protocol.WritePacket(session.conn, pkt)
	session.writeMu.Unlock()
	if err != nil {
		return protocol.EmailProbeResult{}, err
	}

	select {
	case <-ctx.Done():
		return protocol.EmailProbeResult{}, ctx.Err()
	case payload := <-probeCh:
		var res protocol.EmailProbeResult
		if err := json.Unmarshal(payload, &res); err != nil {
			return protocol.EmailProbeResult{}, err
		}
		return res, nil
	}
}

func (s *Server) Run(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	s.Stop()
	return nil
}

const defaultMaxConnsPerRoute = 4096

func NewServer(cfg ServerConfig, appStore *appstore.Store) *Server {
	s := &Server{
		cfg:                  cfg,
		appStore:             appStore,
		derivedKeys:          make(map[string][]byte),
		publicTCP:            make(map[string]net.Listener),
		publicUDP:            make(map[string]*net.UDPConn),
		pendingTCP:           make(map[pendingTCPKey]*pendingTCPEntry),
		dash:                 newDashState(),
		sessions:             make(map[string]*agentSession),
		udpGraceTimers:       make(map[string]*udpGraceTimer),
		probeOutboundTargets: make(map[string]time.Time),
		maxConnsPerRoute:     defaultMaxConnsPerRoute,
		dynamicRoutes:        make(map[string]dynamicRouteEntry),
	}
	s.udpAgents.Store(&map[string]*agentUDPState{})
	s.domains = newDomainManager(s)
	if strings.TrimSpace(cfg.DynamicPortRange) != "" {
		parts := strings.SplitN(strings.TrimSpace(cfg.DynamicPortRange), "-", 2)
		if len(parts) == 2 {
			low, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				logging.Global().Warnf(logging.CatTCP, "invalid dynamic port range low %q: %v", parts[0], err)
			} else {
				s.dynamicPortLow = low
			}
			high, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				logging.Global().Warnf(logging.CatTCP, "invalid dynamic port range high %q: %v", parts[1], err)
			} else {
				s.dynamicPortHigh = high
			}
		}
	}
	if s.dynamicPortLow == 0 {
		s.dynamicPortLow = 10000
	}
	if s.dynamicPortHigh == 0 {
		s.dynamicPortHigh = 60000
	}
	for _, rt := range effectiveRoutes(cfg, s.dynamicRoutes) {
		if rt.IsEncrypted() {
			if key := s.encryptionBaseKey(); key != nil {
				s.derivedKeys[rt.Name] = key
			}
		}
	}
	if appStore != nil {
		apps, err := appStore.ListApplications(context.Background())
		if err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to load persisted applications: %v", err)
		} else {
			for _, app := range apps {
				for _, route := range app.Routes {
					enc := route.Encrypted
					domainEnabled := route.DomainEnabled
					rt := RouteConfig{
						Name:          route.RouteName,
						Proto:         route.Proto,
						PublicAddr:    route.PublicAddr,
						LocalAddr:     route.LocalAddr,
						Agent:         route.AgentID,
						Enabled:       boolPtr(route.Enabled),
						Encrypted:     &enc,
						Domain:        route.Domain,
						DomainEnabled: &domainEnabled,
					}
					s.dynamicRoutes[route.RouteName] = dynamicRouteEntry{
						Route:     rt,
						CreatedAt: route.CreatedAt,
						Source:    "api",
					}
					if enc {
						if key := s.encryptionBaseKey(); key != nil {
							s.derivedKeys[route.RouteName] = key
						}
					}
				}
			}
		}
	}
	s.updateRouteCache()
	return s
}

func (s *Server) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	// Shared flusher for byte counters; avoids a goroutine per connection.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(dashBatchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.flushCounters()
			}
		}
	}()

	var controlLn net.Listener
	var dataLn net.Listener
	var err error

	if s.cfg.DisableTLS {
		controlLn, err = net.Listen("tcp", s.cfg.ControlAddr)
		if err != nil {
			return fmt.Errorf("control listen failed: %w", err)
		}
		dataLn, err = net.Listen("tcp", s.cfg.DataAddr)
		if err != nil {
			controlLn.Close()
			return fmt.Errorf("data listen failed: %w", err)
		}
	} else {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS cert: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		controlLn, err = tls.Listen("tcp", s.cfg.ControlAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("control tls listen failed: %w", err)
		}
		dataLn, err = tls.Listen("tcp", s.cfg.DataAddr, tlsConfig)
		if err != nil {
			controlLn.Close()
			return fmt.Errorf("data tls listen failed: %w", err)
		}
	}

	s.controlLn = controlLn
	s.wg.Add(1)
	go s.acceptControl(controlLn)

	s.dataLn = dataLn
	s.wg.Add(1)
	go s.acceptData(dataLn)

	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.DataAddr)
	if err != nil {
		return fmt.Errorf("resolve udp data addr failed: %w", err)
	}
	s.udpDataConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("udp data listen failed: %w", err)
	}
	bufferResult := netutil.SetUDPBuffers(s.udpDataConn, sharedUDPReadBufferBytes, sharedUDPWriteBufferBytes)
	if bufferResult.ReadErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request shared UDP read buffer bytes=%d: %v", bufferResult.ReadBytes, bufferResult.ReadErr)
	}
	if bufferResult.WriteErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request shared UDP write buffer bytes=%d: %v", bufferResult.WriteBytes, bufferResult.WriteErr)
	}
	s.udpEgress, err = newServerUDPEgress(s, s.udpDataConn)
	if err != nil {
		s.udpDataConn.Close()
		return fmt.Errorf("create UDP egress scheduler: %w", err)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.udpEgress.run(s.ctx)
	}()
	s.wg.Add(1)
	go s.acceptAgentUDP()

	for _, rt := range effectiveRoutes(s.cfg, s.dynamicRoutes) {
		if strings.TrimSpace(rt.PublicAddr) != "" && (rt.Proto == routeProtoTCP || rt.Proto == routeProtoBoth) {
			ln, err := net.Listen("tcp", rt.PublicAddr)
			if err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to listen on public tcp %s: %v", rt.PublicAddr, err)
				continue
			}
			s.mu.Lock()
			s.publicTCP[rt.Name] = ln
			s.mu.Unlock()
			s.wg.Add(1)
			go s.acceptPublicTCP(ln, rt.Name)
		}
		if strings.TrimSpace(rt.PublicAddr) != "" && (rt.Proto == routeProtoUDP || rt.Proto == routeProtoBoth) {
			addr, err := net.ResolveUDPAddr("udp", rt.PublicAddr)
			if err != nil {
				logging.Global().Errorf(logging.CatUDP, "failed to resolve public udp %s: %v", rt.PublicAddr, err)
				continue
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				logging.Global().Errorf(logging.CatUDP, "failed to listen on public udp %s: %v", rt.PublicAddr, err)
				continue
			}
			configureRouteUDPSocket(conn, rt.Name)
			s.mu.Lock()
			s.publicUDP[rt.Name] = conn
			s.publishPublicUDPLocked()
			s.mu.Unlock()
			s.wg.Add(1)
			go s.acceptPublicUDP(conn, rt.Name)
		}
	}

	if err := s.startDomainGateway(); err != nil {
		return err
	}

	logging.Global().Infof(logging.CatSystem, "Server started on control=%s data=%s", s.cfg.ControlAddr, s.cfg.DataAddr)
	if s.cfg.DisableTLS {
		logging.Global().Warnf(logging.CatEncryption, "TLS is disabled (DisableTLS=true). The control channel and authentication handshake run in plaintext. This is only safe on fully trusted networks. Combine with per-session WrapTCP.")
	}
	return nil
}

func (s *Server) Stop() {
	s.stopping.Store(true)
	s.helloMu.Lock()
	if s.helloTimer != nil {
		s.helloTimer.Stop()
		s.helloTimer = nil
	}
	s.helloPending = false
	s.helloMu.Unlock()
	s.stopUDPGraceTimers()

	if s.cancel != nil {
		s.cancel()
	}
	if s.udpEgress != nil {
		s.udpEgress.close()
	}
	if s.controlLn != nil {
		s.controlLn.Close()
	}
	if s.dataLn != nil {
		s.dataLn.Close()
	}
	if s.udpDataConn != nil {
		s.udpDataConn.Close()
	}

	// Control readers otherwise remain blocked until their read deadline. Clear
	// the authoritative map first so deferred cleanup cannot schedule a shutdown
	// grace timer, then cancel and close sessions outside sessionsMu.
	s.sessionsMu.Lock()
	sessions := make([]*agentSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.sessions = make(map[string]*agentSession)
	s.sessionsMu.Unlock()
	for _, session := range sessions {
		if session.cancel != nil {
			session.cancel()
		}
		if session.conn != nil {
			session.conn.Close()
		}
	}
	if s.domainHTTPServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), domainShutdownTimeout)
		_ = s.domainHTTPServer.Shutdown(ctx)
		cancel()
	}
	if s.domainHTTPSServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), domainShutdownTimeout)
		_ = s.domainHTTPSServer.Shutdown(ctx)
		cancel()
	}
	if s.domainHTTPLn != nil {
		s.domainHTTPLn.Close()
	}
	if s.domainHTTPSLn != nil {
		s.domainHTTPSLn.Close()
	}
	s.closeDomainProxyIdleConnections()
	// Route handlers mutate these maps under s.mu. Snapshot and clear them under
	// the same lock so shutdown cannot race iteration or retain a published UDP
	// listener after the snapshot.
	s.mu.Lock()
	publicTCP := make([]net.Listener, 0, len(s.publicTCP))
	for _, ln := range s.publicTCP {
		publicTCP = append(publicTCP, ln)
	}
	publicUDP := make([]*net.UDPConn, 0, len(s.publicUDP))
	for _, conn := range s.publicUDP {
		publicUDP = append(publicUDP, conn)
	}
	s.publicTCP = make(map[string]net.Listener)
	s.publicUDP = make(map[string]*net.UDPConn)
	s.publishPublicUDPLocked()
	s.abortPendingTCPLocked()
	s.mu.Unlock()
	for _, ln := range publicTCP {
		ln.Close()
	}
	for _, conn := range publicUDP {
		conn.Close()
	}
	s.wg.Wait()
	// A live control goroutine can schedule its disconnect grace while Stop is
	// closing listeners. Once every producer has exited, drain timers again so
	// Stop never returns with a callback retaining or mutating this server.
	s.stopUDPGraceTimers()
}

// rejectVersion tells an authenticated peer why its negotiation failed
// (best effort) before closing, so the agent reports the precise reason
// instead of a bare connection reset.
func (s *Server) rejectVersion(conn net.Conn, reason string) {
	payload, err := json.Marshal(protocol.VersionPayload{Version: protocol.ProtocolVersion, Error: reason})
	if err == nil {
		conn.SetWriteDeadline(time.Now().Add(writeDeadlineShort))
		_ = protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeVersionNegotiate, Payload: payload})
	}
	conn.Close()
}

// rejectIdentityConflict tells an agent its proposed ID belongs to another
// agent, so it should regenerate a new ID and reconnect.
func (s *Server) rejectIdentityConflict(conn net.Conn) {
	payload, err := json.Marshal(protocol.VersionPayload{Version: protocol.ProtocolVersion, Conflict: true})
	if err == nil {
		conn.SetWriteDeadline(time.Now().Add(writeDeadlineShort))
		_ = protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeVersionNegotiate, Payload: payload})
	}
	conn.Close()
}

func (s *Server) acceptControl(ln net.Listener) {
	defer s.wg.Done()
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			logging.Global().Errorf(logging.CatTCP, "control accept error: %v", err)
			continue
		}
		netutil.SetTCPKeepAlive(conn, tcpKeepAliveInterval)
		netutil.SetTCPNoDelay(conn)

		conn.SetDeadline(time.Now().Add(authDeadline))
		_, serverNonce, err := crypto.AuthenticateServer(conn, s.cfg.Token)
		if err != nil {
			logging.Global().Errorf(logging.CatTCP, "control auth failed from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}
		conn.SetDeadline(time.Time{})

		remoteAddr := conn.RemoteAddr().String()

		// Version negotiation runs BEFORE this connection touches any agent
		// state: a peer that fails it must not bump the epoch, abort pending
		// pairs, or displace a healthy connected agent (an old-version agent
		// stuck in a reconnect loop would otherwise take the tunnel down
		// every retry).
		conn.SetReadDeadline(time.Now().Add(authDeadline))
		var verPkt protocol.Packet
		if err := protocol.ReadPacketTo(conn, &verPkt); err != nil {
			logging.Global().Errorf(logging.CatTCP, "version negotiate read failed from %s: %v", remoteAddr, err)
			conn.Close()
			continue
		}
		conn.SetReadDeadline(time.Time{})
		if verPkt.Type != protocol.TypeVersionNegotiate {
			logging.Global().Errorf(logging.CatTCP, "expected version negotiate from %s, got type %d", remoteAddr, verPkt.Type)
			s.rejectVersion(conn, "first packet after auth must be version negotiation")
			continue
		}
		var vp protocol.VersionPayload
		if err := json.Unmarshal(verPkt.Payload, &vp); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to parse version negotiate from %s: %v", remoteAddr, err)
			s.rejectVersion(conn, "malformed version negotiation payload")
			continue
		}
		agentVer, ok := version.Parse(vp.Version)
		if !ok {
			logging.Global().Errorf(logging.CatTCP, "agent sent invalid version from %s: %s", remoteAddr, vp.Version)
			s.rejectVersion(conn, fmt.Sprintf("invalid protocol version %q", vp.Version))
			continue
		}
		if !protocol.IsCompatibleWith(protocol.ProtocolVersionParsed, agentVer) {
			reason := protocol.IncompatibleVersionError(protocol.ProtocolVersionParsed, agentVer)
			logging.Global().Errorf(logging.CatTCP, "rejecting agent from %s: %s", remoteAddr, reason)
			s.rejectVersion(conn, reason)
			continue
		}
		features := protocol.NegotiateFeatures(protocol.SupportedFeatures, vp.Features)
		if !protocol.HasFeature(features, protocol.FeatureBoundUDPRegister) {
			reason := fmt.Sprintf("protocol %s requires feature %q", protocol.ProtocolVersion, protocol.FeatureBoundUDPRegister)
			logging.Global().Errorf(logging.CatTCP, "rejecting agent from %s: %s", remoteAddr, reason)
			s.rejectVersion(conn, reason)
			continue
		}
		agentID := strings.TrimSpace(vp.AgentID)
		if agentID == "" {
			agentID = protocol.DefaultAgentID
		}
		if len(agentID) > crypto.MaxAgentIDLen {
			logging.Global().Errorf(logging.CatTCP, "agent from %s sent oversized agent ID (%d bytes)", remoteAddr, len(agentID))
			s.rejectVersion(conn, "agent id too long")
			continue
		}

		// Prove the agent holds the key bound to this ID by verifying its
		// signature over our auth nonce, then arbitrate the ID via the registry.
		if len(vp.PublicKey) != crypto.AgentPublicKeyLen || !crypto.VerifyIdentityChallenge(vp.PublicKey, serverNonce, vp.IdentitySig) {
			logging.Global().Errorf(logging.CatTCP, "agent %q from %s failed identity verification", agentID, remoteAddr)
			s.rejectVersion(conn, "agent identity signature invalid")
			continue
		}
		controlNonce, ok := crypto.NewUDPControlNonce(serverNonce)
		if !ok {
			logging.Global().Errorf(logging.CatTCP, "internal control nonce length mismatch for agent %q", agentID)
			s.rejectVersion(conn, "invalid control-session nonce")
			continue
		}
		if s.appStore != nil {
			resolved, conflict, rerr := s.appStore.ResolveAgent(s.ctx, vp.PublicKey, agentID)
			if rerr != nil {
				logging.Global().Errorf(logging.CatTCP, "agent registry error for %q from %s: %v", agentID, remoteAddr, rerr)
				s.rejectVersion(conn, "agent registry error")
				continue
			}
			if conflict {
				logging.Global().Warnf(logging.CatTCP, "agent id %q from %s belongs to another agent; requesting a new id", agentID, remoteAddr)
				s.rejectIdentityConflict(conn)
				continue
			}
			if resolved != agentID {
				logging.Global().Infof(logging.CatTCP, "agent from %s proposed %q, assigned registered id %q", remoteAddr, agentID, resolved)
			}
			agentID = resolved
		}
		logging.Global().Infof(logging.CatTCP, "Agent %q version negotiated from %s: %s features=%v", agentID, remoteAddr, agentVer, features)

		verPayload, _ := json.Marshal(protocol.VersionPayload{Version: protocol.ProtocolVersion, Features: protocol.SupportedFeatures, AssignedAgentID: agentID})
		conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
		if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeVersionNegotiate, Payload: verPayload}); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to send version negotiate to %s: %v", remoteAddr, err)
			conn.Close()
			continue
		}

		// Adopt after the version response but before HELLO. Receiving HELLO now
		// guarantees the agent can immediately register against an installed
		// control generation instead of racing this state transition.
		var oldSession *agentSession
		s.sessionsMu.Lock()
		if s.stopping.Load() {
			s.sessionsMu.Unlock()
			conn.Close()
			continue
		}
		if existing := s.sessions[agentID]; existing != nil {
			oldSession = existing
		}
		sessionCtx, sessionCancel := context.WithCancel(s.ctx)
		session := &agentSession{
			conn:              conn,
			cancel:            sessionCancel,
			agentID:           agentID,
			remoteAddr:        remoteAddr,
			connectTime:       time.Now(),
			identityPublicKey: append([]byte(nil), vp.PublicKey...),
			controlNonce:      controlNonce,
			features:          features,
		}
		// Once published, broadcastHello and CONNECT producers may obtain this
		// session immediately. Hold its write lock across publication and the
		// initial HELLO so no later control frame can overtake or interleave it.
		session.writeMu.Lock()
		s.sessions[agentID] = session
		// Bound any previously published generation while the replacement
		// proves its UDP endpoint. A valid new registration cancels this timer.
		s.scheduleUDPAgentClearLocked(agentID)
		s.sessionsMu.Unlock()

		if oldSession != nil {
			logging.Global().Infof(logging.CatTCP, "Terminating previous session for agent %q (%s)", agentID, oldSession.remoteAddr)
			if oldSession.cancel != nil {
				oldSession.cancel()
			}
			if oldSession.conn != nil {
				oldSession.conn.Close()
			}
		}

		// Build only after publication while holding writeMu. A route mutation
		// before this point is included here; a later broadcast must acquire the
		// same lock before taking its own snapshot, so HELLO snapshots cannot be
		// delivered in reverse freshness order.
		helloPkt, err := s.buildHelloPacketForAgent(agentID)
		if err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to build HELLO packet: %v", err)
			s.sessionsMu.Lock()
			if s.sessions[agentID] == session {
				delete(s.sessions, agentID)
				s.scheduleUDPAgentClearLocked(agentID)
			}
			s.sessionsMu.Unlock()
			sessionCancel()
			conn.Close()
			session.writeMu.Unlock()
			continue
		}
		conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
		if err := protocol.WritePacket(conn, helloPkt); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to send HELLO: %v", err)
			s.sessionsMu.Lock()
			if s.sessions[agentID] == session {
				delete(s.sessions, agentID)
				s.scheduleUDPAgentClearLocked(agentID)
			}
			s.sessionsMu.Unlock()
			sessionCancel()
			conn.Close()
			session.writeMu.Unlock()
			continue
		}
		conn.SetWriteDeadline(time.Time{})
		session.writeMu.Unlock()

		s.mu.Lock()
		s.lastAgentConnectAt = time.Now()
		s.abortPendingTCPForAgentLocked(agentID)
		s.mu.Unlock()

		// Serialize the final Add with Stop's session snapshot. If shutdown won
		// the race, the published session has already been canceled and closed.
		s.sessionsMu.Lock()
		if s.stopping.Load() || s.sessions[agentID] != session {
			s.sessionsMu.Unlock()
			sessionCancel()
			conn.Close()
			continue
		}
		s.wg.Add(1)
		s.sessionsMu.Unlock()
		logging.Global().Infof(logging.CatTCP, "Agent %q connected to control from %s", agentID, remoteAddr)

		go func(c net.Conn, session *agentSession, agentID string) {
			defer s.wg.Done()
			defer func() {
				c.Close()
				s.sessionsMu.Lock()
				if s.sessions[agentID] == session {
					delete(s.sessions, agentID)
					s.scheduleUDPAgentClearLocked(agentID)
				}
				s.sessionsMu.Unlock()
			}()

			pingCtx, pingCancel := context.WithCancel(sessionCtx)
			defer pingCancel()

			var lastPong atomic.Value
			lastPong.Store(time.Now().UnixNano())

			go func() {
				ticker := time.NewTicker(pingInterval)
				defer ticker.Stop()
				for {
					select {
					case <-pingCtx.Done():
						return
					case <-ticker.C:
						if s.isCurrentSession(agentID, session) {
							session.writeMu.Lock()
							c.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
							if err := protocol.WritePacket(c, &protocol.Packet{Type: protocol.TypePing}); err != nil {
								session.writeMu.Unlock()
								c.Close()
								return
							}
							session.writeMu.Unlock()
						}
					}
				}
			}()

			go func() {
				ticker := time.NewTicker(healthCheckInterval)
				defer ticker.Stop()
				for {
					select {
					case <-pingCtx.Done():
						return
					case <-ticker.C:
						if s.isCurrentSession(agentID, session) {
							lastPongTime := time.Unix(0, lastPong.Load().(int64))
							if time.Since(lastPongTime) > healthCheckTimeout {
								logging.Global().Errorf(logging.CatTCP, "agent health check timeout, closing connection")
								c.Close()
								return
							}
						}
					}
				}
			}()

			connStart := time.Now()
			var pkt protocol.Packet
			deadlineAt := time.Now().Add(readDeadlineStandard)
			c.SetReadDeadline(deadlineAt)
			for {
				select {
				case <-sessionCtx.Done():
					return
				default:
				}

				if time.Since(connStart) > maxControlConnLifetime {
					logging.Global().Warnf(logging.CatTCP, "control connection lifetime exceeded, closing")
					break
				}

				if err := protocol.ReadPacketTo(c, &pkt); err != nil {
					break
				}
				deadlineAt = time.Now().Add(readDeadlineStandard)
				c.SetReadDeadline(deadlineAt)
				if pkt.Type == protocol.TypePing {
					session.writeMu.Lock()
					c.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
					protocol.WritePacket(c, &protocol.Packet{
						Type:    protocol.TypePong,
						Payload: pkt.Payload,
					})
					session.writeMu.Unlock()
					continue
				}
				if pkt.Type == protocol.TypePong {
					lastPong.Store(time.Now().UnixNano())
					s.mu.RLock()
					ch := s.pongCh
					s.mu.RUnlock()
					if ch != nil {
						select {
						case ch <- pkt.Payload:
						default:
						}
					}
				}
				if pkt.Type == protocol.TypeEmailProbeResult {
					s.mu.RLock()
					ch := s.emailProbeCh
					s.mu.RUnlock()
					if ch != nil {
						select {
						case ch <- pkt.Payload:
						default:
						}
					}
				}
				if pkt.Type == protocol.TypeRouteRequest {
					s.handleRouteRequest(c, session, pkt.Payload)
					continue
				}
				if pkt.Type == protocol.TypeRouteConfirm {
					s.handleRouteConfirm(c, session, pkt.Payload)
					continue
				}
				if pkt.Type == protocol.TypeRouteRemove {
					s.handleRouteRemove(c, session, pkt.Payload)
					continue
				}
				if pkt.Type == protocol.TypeRouteUpdate {
					s.handleRouteUpdate(c, session, pkt.Payload)
					continue
				}
			}

			if s.isCurrentSession(agentID, session) {
				s.mu.Lock()
				s.lastAgentDisconnectAt = time.Now()
				s.closeDomainProxyIdleConnections()
				s.abortPendingTCPForAgentLocked(agentID)
				s.mu.Unlock()
				logging.Global().Infof(logging.CatTCP, "Agent %q disconnected from control", agentID)
			}
		}(conn, session, agentID)
	}
}

func (s *Server) acceptData(ln net.Listener) {
	defer s.wg.Done()
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			logging.Global().Errorf(logging.CatTCP, "data accept error: %v", err)
			continue
		}
		netutil.SetTCPKeepAlive(conn, tcpKeepAliveInterval)
		netutil.SetTCPNoDelay(conn)

		handshakeDL := time.Now().Add(handshakeDeadline)
		conn.SetDeadline(handshakeDL)
		clientNonce, serverNonce, err := crypto.AuthenticateServer(conn, s.cfg.Token)
		if err != nil {
			logging.Global().Errorf(logging.CatTCP, "data auth failed from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}
		conn.SetReadDeadline(handshakeDL)

		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			conn.Close()
			continue
		}
		routeBytes := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, routeBytes); err != nil {
			conn.Close()
			continue
		}

		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			conn.Close()
			continue
		}
		clientBytes := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, clientBytes); err != nil {
			conn.Close()
			continue
		}
		clientID := string(clientBytes)
		conn.SetReadDeadline(handshakeDL)

		routeName := string(routeBytes)
		if routeName == protocol.RouteMailOutboundTCP {
			target := string(clientBytes)
			s.dialMailOutboundTCP(conn, target)
			continue
		}

		// Pairing token is sent in the clear before optional tunnel encryption.
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			conn.Close()
			continue
		}
		pairBytes := make([]byte, lenBuf[0])
		if lenBuf[0] > 0 {
			if _, err := io.ReadFull(conn, pairBytes); err != nil {
				conn.Close()
				continue
			}
		}

		rc, _ := s.getRouteConfig(routeName)
		isEncrypted := rc.isEncrypted

		if isEncrypted {
			key := rc.derivedKey
			if key == nil {
				logging.Global().Errorf(logging.CatTCP, "failed to derive key for route %s: key is nil", routeName)
				conn.Close()
				continue
			}
			conn, err = crypto.WrapTCP(conn, key, clientNonce, serverNonce, false)
			if err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to wrap tcp for route %s: %v", routeName, err)
				conn.Close()
				continue
			}
		}

		pendingKey := makePendingTCPKey(routeName, clientID)
		s.mu.Lock()
		entry, ok := s.pendingTCP[pendingKey]
		if ok {
			delete(s.pendingTCP, pendingKey)
		}
		s.mu.Unlock()

		if !ok {
			logging.Global().RateLimitedWarn(logging.CatTCP, "data-unmatched-"+routeName, fmt.Sprintf("data handshake with no pending pairing route=%s client=%s from=%s", routeName, clientID, conn.RemoteAddr()))
			conn.Close()
			continue
		}
		if len(entry.pairToken) > 0 && subtle.ConstantTimeCompare(entry.pairToken, pairBytes) != 1 {
			logging.Global().RateLimitedWarn(logging.CatTCP, "data-pair-token-"+routeName, fmt.Sprintf("rejected data pairing with bad token route=%s client=%s from=%s", routeName, clientID, conn.RemoteAddr()))
			conn.Close()
			entry.cancel()
			continue
		}
		if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
			if entry.controlRemote != "" && !controlPeerIPMatches(entry.controlRemote, ap) {
				logging.Global().RateLimitedWarn(logging.CatTCP, "data-pair-ip-"+routeName, fmt.Sprintf("rejected data pairing from %s; control peer is %s route=%s client=%s", conn.RemoteAddr(), entry.controlRemote, routeName, clientID))
				conn.Close()
				entry.cancel()
				continue
			}
		}
		// SetDeadline above armed both read and write. Clearing only the
		// read side left a ~15s write deadline on domain keep-alive conns
		// returned by dialRouteTCP (public relays overwrite it via idle
		// timeout wrappers). Clear both before handing the conn off.
		_ = conn.SetDeadline(time.Time{})
		entry.deliver(conn)
	}
}

func (s *Server) acceptPublicTCP(ln net.Listener, routeName string) {
	defer s.wg.Done()
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			logging.Global().Errorf(logging.CatTCP, "public tcp accept error: %v", err)
			continue
		}

		semVal, _ := s.connSemaphores.LoadOrStore(routeName, make(chan struct{}, s.maxConnsPerRoute))
		sem, ok := semVal.(chan struct{})
		if !ok {
			logging.Global().Errorf(logging.CatTCP, "invalid semaphore type for route=%s, rejecting", routeName)
			conn.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			logging.Global().Warnf(logging.CatTCP, "connection limit reached for route=%s, rejecting", routeName)
			conn.Close()
			continue
		}

		netutil.SetTCPKeepAlive(conn, tcpKeepAliveInterval)
		netutil.SetTCPNoDelay(conn)
		// Reap public peers that vanish without a clean shutdown quickly,
		// so the relay (and the agent's downstream session) is freed
		// before the relay idle timeout.
		netutil.TuneDeadPeerDetection(conn)
		clientID := s.nextClientID()
		logging.Global().Infof(logging.CatTCP, "New public TCP connection route=%s client=%s", routeName, clientID)

		rc, ok := s.getRouteConfig(routeName)
		enabled := ok && rc.enabled
		owner := rc.owner
		if owner == "" {
			owner = protocol.DefaultAgentID
		}
		session, sessionOK := s.sessionForAgent(owner)

		if !sessionOK || !enabled {
			<-sem
			if isEmailRoute(routeName) {
				logging.Global().Warnf(logging.CatTCP, "mail public connection rejected route=%s owner=%s agentConnected=%v enabled=%v", routeName, owner, sessionOK, enabled)
				writeMailRouteUnavailable(conn, routeName)
			}
			conn.Close()
			continue
		}

		entry := newPendingTCPPair(owner, session.remoteAddr)
		pendingKey := makePendingTCPKey(routeName, clientID)
		s.mu.Lock()
		s.pendingTCP[pendingKey] = entry
		s.mu.Unlock()

		reqPkt := &protocol.Packet{
			Type:    protocol.TypeConnect,
			Route:   routeName,
			Client:  clientID,
			Payload: entry.pairToken,
		}
		session.writeMu.Lock()
		session.conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
		writeErr := protocol.WritePacket(session.conn, reqPkt)
		session.writeMu.Unlock()
		if writeErr != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to request agent connect route=%s client=%s: %v", routeName, clientID, writeErr)
			<-sem
			writeMailRouteUnavailable(conn, routeName)
			conn.Close()
			s.mu.Lock()
			delete(s.pendingTCP, pendingKey)
			s.mu.Unlock()
			entry.cancel()
			continue
		}

		go func(c net.Conn, clientID string, sem chan struct{}) {
			defer c.Close()
			defer func() { <-sem }()
			timer := time.NewTimer(s.cfg.PairTimeout)
			defer timer.Stop()
			select {
			case <-entry.done:
				logging.Global().Warnf(logging.CatTCP, "agent pairing aborted route=%s client=%s", routeName, clientID)
				writeMailRouteUnavailable(c, routeName)
				return
			case <-entry.ready:
				agentConn := entry.take()
				if agentConn == nil {
					logging.Global().Warnf(logging.CatTCP, "agent pairing missing backend route=%s client=%s", routeName, clientID)
					writeMailRouteUnavailable(c, routeName)
					return
				}
				logging.Global().Infof(logging.CatTCP, "paired public TCP route=%s client=%s", routeName, clientID)
				s.dash.addConn(time.Now())
				s.dash.incActive(routeName)
				defer s.dash.decActive(routeName)

				s.runCountedRelay(routeName, c, agentConn)

			case <-timer.C:
				// Race: delivery may have landed at the same moment the
				// timer fired. Use it instead of discarding a valid pair.
				agentConn := entry.take()
				if agentConn != nil {
					logging.Global().Infof(logging.CatTCP, "paired public TCP route=%s client=%s (race recovery)", routeName, clientID)
					s.dash.addConn(time.Now())
					s.dash.incActive(routeName)
					defer s.dash.decActive(routeName)

					s.runCountedRelay(routeName, c, agentConn)
					return
				}
				logging.Global().Warnf(logging.CatTCP, "pair timeout route=%s client=%s", routeName, clientID)
				s.mu.Lock()
				delete(s.pendingTCP, pendingKey)
				s.mu.Unlock()
				entry.cancel()
				writeMailRouteUnavailable(c, routeName)
			}
		}(conn, clientID, sem)
	}
}

// runCountedRelay wraps the public + agent leg in countingConns and runs
// the relay. The shared flusher goroutine on the Server periodically
// drains the byte counters into the dashboard, so the per-connection
// overhead is just the atomic adds inside each Read.
func (s *Server) runCountedRelay(routeName string, publicConn, agentConn net.Conn) {
	pubCounter := &countingConn{Conn: publicConn}
	agtCounter := &countingConn{Conn: agentConn}
	s.registerCounters(pubCounter, agtCounter)
	defer s.unregisterCounters(pubCounter, agtCounter)
	relay.ProxyWithIdleTimeout(pubCounter, agtCounter, proxyIdleTimeout)
	now := time.Now()
	if n := pubCounter.Flush(); n > 0 {
		s.dash.addBytes(now, n)
	}
	if n := agtCounter.Flush(); n > 0 {
		s.dash.addBytes(now, n)
	}
}

type counterRegistry struct {
	mu     sync.Mutex
	active map[*countingConn]struct{}
}

func (s *Server) registerCounters(pub, agt *countingConn) {
	s.counters.mu.Lock()
	if s.counters.active == nil {
		s.counters.active = make(map[*countingConn]struct{}, 64)
	}
	s.counters.active[pub] = struct{}{}
	s.counters.active[agt] = struct{}{}
	s.counters.mu.Unlock()
}

func (s *Server) unregisterCounters(pub, agt *countingConn) {
	s.counters.mu.Lock()
	delete(s.counters.active, pub)
	delete(s.counters.active, agt)
	s.counters.mu.Unlock()
}

func (s *Server) flushCounters() {
	s.counters.mu.Lock()
	counters := make([]*countingConn, 0, len(s.counters.active))
	for c := range s.counters.active {
		counters = append(counters, c)
	}
	s.counters.mu.Unlock()
	if len(counters) == 0 {
		return
	}
	now := time.Now()
	for _, c := range counters {
		if n := c.Flush(); n > 0 {
			s.dash.addBytes(now, n)
		}
	}
}

// countingConn atomically accumulates bytes that flow through Read. The
// per-Read cost is a single atomic add; the shared flusher calls Flush
// periodically to push totals to the dashboard.
type countingConn struct {
	net.Conn
	pending atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.pending.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Flush() int64 {
	return c.pending.Swap(0)
}

func (c *countingConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return c.Conn.Close()
}

func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (s *Server) acceptAgentUDP() {
	defer s.wg.Done()
	defer s.udpDataConn.Close()

	buf := make([]byte, 65536)
	decryptBuf := make([]byte, 65536)
	aadBuf := make([]byte, 0, 512)
	// Route/client strings repeat on every datagram of a flow; interning
	// removes both per-packet string allocations.
	interner := protocol.NewStringInterner(4096)
	var pkt protocol.Packet

	var pendingBytes int64
	var pendingBytesTime time.Time
	defer func() {
		if pendingBytes > 0 {
			s.dash.addBytes(pendingBytesTime, pendingBytes)
		}
	}()

	// Deduplicate accepted proofs before taking sessionsMu or running Ed25519
	// verification. Bookkeeping is bounded independently for each live identity.
	seenRegisters := newUDPRegisterReplayCache()
	var lastRegisterReplayPrune int64

	// Two-generation client-addr parse cache: the same client strings repeat
	// on every datagram of a flow, so parsing once per flow avoids the
	// per-packet netip.ParseAddrPort cost.
	const maxClientAddrCache = 10000 / 2
	clientAddrCur := make(map[string]netip.AddrPort)
	var clientAddrPrev map[string]netip.AddrPort
	type publicWriteDeadlineState struct {
		conn *net.UDPConn
		set  time.Time
	}
	publicWriteDeadlines := make(map[string]publicWriteDeadlineState)

	for {
		n, addr, err := s.udpDataConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}

		err = protocol.UnmarshalUDPToInterned(buf[:n], &pkt, interner)
		if err != nil {
			continue
		}

		if pkt.Type == protocol.TypeRegister {
			// A v3 peer must prove its identity, UDP session, and exact live control
			// generation before the observed source is adopted. Source-IP equality
			// is deliberately unnecessary for split-path/NAT deployments. The signed
			// nonce blocks token-only impersonation, and the replay cache prevents a
			// proof from moving the endpoint again after its first accepted use.
			nowT := time.Now()
			reg, ok := crypto.ParseBoundUDPRegister(s.cfg.Token, pkt.Payload, nowT, udpRegisterAuthWindow)
			if !ok {
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-register-reject", fmt.Sprintf("rejected malformed/unauthenticated bound UDP register from %s", addr))
				continue
			}
			if reg.AgentID == "" {
				reg.AgentID = protocol.DefaultAgentID
			}
			nowNano := nowT.UnixNano()
			if nowNano-lastRegisterReplayPrune >= int64(udpRegisterAuthWindow/2) {
				seenRegisters.prune(nowNano)
				lastRegisterReplayPrune = nowNano
			}
			if seen, full := seenRegisters.status(reg.AgentID, reg.ControlNonce, reg.Key, nowNano); seen || full {
				continue
			}

			s.sessionsMu.Lock()
			sess := s.sessions[reg.AgentID]
			if sess == nil {
				s.sessionsMu.Unlock()
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-register-nosession", fmt.Sprintf("rejected UDP register for agent %q from %s: no live control session", reg.AgentID, addr))
				continue
			}
			if !protocol.HasFeature(sess.features, protocol.FeatureBoundUDPRegister) || sess.controlNonce != reg.ControlNonce || !reg.VerifyIdentity(sess.identityPublicKey) {
				s.sessionsMu.Unlock()
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-register-generation", fmt.Sprintf("rejected UDP register for agent %q from %s: identity/control generation mismatch", reg.AgentID, addr))
				continue
			}

			if !seenRegisters.record(reg.AgentID, reg.ControlNonce, reg.Key, reg.ValidUntil().UnixNano(), nowNano) {
				s.sessionsMu.Unlock()
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-register-rate-"+reg.AgentID, fmt.Sprintf("rejected excessive UDP registrations for agent %q from %s", reg.AgentID, addr))
				continue
			}

			s.udpAgentsMu.Lock()
			prev := s.loadUDPAgents()[reg.AgentID]
			if prev == nil {
				logging.Global().Infof(logging.CatUDP, "Agent %q UDP address registered: %s", reg.AgentID, addr.String())
			} else if prev.addr != addr {
				logging.Global().Infof(logging.CatUDP, "Agent %q UDP address updated: %s", reg.AgentID, addr.String())
			}
			s.updateUDPAgentAddrLocked(reg.AgentID, addr, reg.SessionID, reg.ControlNonce, nowNano)
			s.pruneUDPAgentsLocked(nowNano)
			s.udpAgentsMu.Unlock()
			s.sessionsMu.Unlock()
			continue
		}

		if pkt.Type == protocol.TypeData {
			routeName := pkt.Route
			clientID := pkt.Client

			// One route-cache load yields owner, enabled, and encryption.
			rc, rcOK := s.getRouteConfig(routeName)
			if !rcOK || !rc.enabled {
				continue
			}
			owner := rc.owner
			if owner == "" {
				owner = protocol.DefaultAgentID
			}
			// Accept tunneled data only from the route owner's registered address.
			st := s.loadUDPAgents()[owner]
			if st == nil || st.addr != addr {
				continue
			}
			// Active data refreshes liveness (throttled).
			now := time.Now().UnixNano()
			if now-st.lastSeen.Load() > int64(500*time.Millisecond) {
				st.lastSeen.Store(now)
			}

			pubConn, ok := s.loadPublicUDP()[routeName]
			if !ok {
				continue
			}

			payload := pkt.Payload
			if rc.isEncrypted {
				if st.crypto == nil {
					continue
				}
				aadBuf = crypto.AppendUDPDataAAD(aadBuf[:0], routeName, clientID)
				decrypted, err := st.crypto.dec.Open(decryptBuf, payload, aadBuf)
				if err != nil {
					s.udpDrops.Add(1)
					logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-open-"+routeName, fmt.Sprintf("dropping undecryptable UDP packet route=%s client=%s err=%v", routeName, clientID, err))
					continue
				}
				payload = decrypted
			}

			clientAddrPort, cached := clientAddrCur[clientID]
			if !cached {
				if clientAddrPort, cached = clientAddrPrev[clientID]; !cached {
					ap, err := netip.ParseAddrPort(clientID)
					if err != nil {
						continue
					}
					clientAddrPort = ap
				}
				if len(clientAddrCur) >= maxClientAddrCache {
					clientAddrPrev = clientAddrCur
					clientAddrCur = make(map[string]netip.AddrPort, 64)
				}
				clientAddrCur[clientID] = clientAddrPort
			}

			pendingBytes += int64(len(payload))
			if pendingBytesTime.IsZero() {
				pendingBytesTime = time.Now()
			} else if time.Since(pendingBytesTime) > dashBatchInterval {
				s.dash.addBytes(pendingBytesTime, pendingBytes)
				pendingBytes = 0
				pendingBytesTime = time.Time{}
			}
			nowT := time.Now()
			deadlineState := publicWriteDeadlines[routeName]
			if deadlineState.conn != pubConn || nowT.Sub(deadlineState.set) >= sharedUDPWriteDeadlineRefresh {
				if err := pubConn.SetWriteDeadline(nowT.Add(sharedUDPWriteTimeout)); err != nil {
					logging.Global().RateLimitedWarn(logging.CatUDP, "server-public-udp-write-deadline-"+routeName, fmt.Sprintf("failed to bound public UDP write route=%s: %v", routeName, err))
				}
				publicWriteDeadlines[routeName] = publicWriteDeadlineState{conn: pubConn, set: nowT}
			}
			written, err := pubConn.WriteToUDPAddrPort(payload, clientAddrPort)
			if err != nil {
				s.udpDrops.Add(1)
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-write-public-"+routeName, fmt.Sprintf("failed to write UDP payload to public client route=%s client=%s bytes=%d err=%v", routeName, clientID, len(payload), err))
				continue
			}
			if written != len(payload) {
				s.udpDrops.Add(1)
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-short-write-public-"+routeName, fmt.Sprintf("short UDP payload write to public client route=%s client=%s wrote=%d want=%d", routeName, clientID, written, len(payload)))
			}
		}
	}
}

func (s *Server) acceptPublicUDP(conn *net.UDPConn, routeName string) {
	defer s.wg.Done()
	defer conn.Close()

	buf := make([]byte, 65536)

	// Two-generation addr->string cache: when the current generation fills,
	// it becomes the previous one and live entries are promoted back on
	// access. Bounded without the churn of evicting random hot entries.
	const maxAddrStrCache = 10000 / 2
	addrStrCur := make(map[netip.AddrPort]string)
	var addrStrPrev map[netip.AddrPort]string
	var pendingBytes int64
	var pendingBytesTime time.Time
	defer func() {
		if pendingBytes > 0 {
			s.dash.addBytes(pendingBytesTime, pendingBytes)
		}
	}()

	for {
		n, addr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}

		clientStr, ok := addrStrCur[addr]
		if !ok {
			if clientStr, ok = addrStrPrev[addr]; !ok {
				clientStr = addr.String()
			}
			if len(addrStrCur) >= maxAddrStrCache {
				addrStrPrev = addrStrCur
				addrStrCur = make(map[netip.AddrPort]string, 64)
			}
			addrStrCur[addr] = clientStr
		}

		rc, rcOK := s.getRouteConfig(routeName)
		if !rcOK || !rc.enabled {
			continue
		}
		owner := rc.owner
		if owner == "" {
			owner = protocol.DefaultAgentID
		}
		st := s.loadUDPAgents()[owner]
		if st == nil || !st.addr.IsValid() {
			s.udpDrops.Add(1)
			continue
		}
		// Owner registration gone stale; acceptAgentUDP prunes it.
		if time.Since(time.Unix(0, st.lastSeen.Load())) > udpRegisterTimeout {
			s.udpDrops.Add(1)
			continue
		}
		pendingBytes += int64(n)
		if pendingBytesTime.IsZero() {
			pendingBytesTime = time.Now()
		} else if time.Since(pendingBytesTime) > dashBatchInterval {
			s.dash.addBytes(pendingBytesTime, pendingBytes)
			pendingBytes = 0
			pendingBytesTime = time.Time{}
		}
		if err := s.udpEgress.enqueue(routeName, clientStr, owner, rc.epoch, st, buf[:n]); err != nil {
			if err != udpfair.ErrFull && err != udpfair.ErrClosed {
				s.udpDrops.Add(1)
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-enqueue-"+routeName, fmt.Sprintf("failed to queue UDP packet route=%s client=%s payload=%d err=%v", routeName, clientStr, n, err))
			}
		}
	}
}

func warnLargeTunneledUDPDatagram(direction, routeName, clientID string, frameLen int) {
	if !protocol.UDPFrameExceedsRecommendedSize(frameLen) {
		return
	}
	logging.Global().RateLimitedWarn(logging.CatUDP, "udp-mtu-"+direction+"-"+routeName, fmt.Sprintf("large tunneled UDP datagram direction=%s route=%s client=%s bytes=%d recommended_max=%d", direction, routeName, clientID, frameLen, protocol.RecommendedMaxUDPDatagramSize))
}
