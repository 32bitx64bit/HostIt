package tunnel

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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
	readDeadlineStandard   = 30 * time.Second
	authDeadline           = 5 * time.Second
	handshakeDeadline      = 15 * time.Second
	pingInterval           = 15 * time.Second
	healthCheckInterval    = 30 * time.Second
	healthCheckTimeout     = 35 * time.Second
	maxControlConnLifetime = 24 * time.Hour
	proxyIdleTimeout       = 5 * time.Minute
	udpRegisterTimeout     = 60 * time.Second
	domainShutdownTimeout  = 5 * time.Second
	nettestTimeout         = 2 * time.Second
	bwTestTimeout          = 5 * time.Second
	emailProbeAllowTTL     = time.Minute
)

type agentSession struct {
	conn        net.Conn
	cancel      context.CancelFunc
	remoteAddr  string
	connectTime time.Time
	writeMu     sync.Mutex
}

type pendingTCPEntry struct {
	mu        sync.Mutex
	conn      net.Conn
	ready     chan struct{}
	done      chan struct{}
	readyOnce sync.Once
	doneOnce  sync.Once
}

func newPendingTCPEntry() *pendingTCPEntry {
	return &pendingTCPEntry{
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
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
	udpCiphers  map[string]cipher.AEAD

	mu            sync.RWMutex
	agentTCP      net.Conn
	agentEpoch    uint64
	agentUDP      netip.AddrPort
	agentUDPAt    time.Time
	udpDataConn   *net.UDPConn
	controlLn     net.Listener
	dataLn        net.Listener
	domainHTTPLn  net.Listener
	domainHTTPSLn net.Listener

	publicTCP         map[string]net.Listener
	publicUDP         map[string]*net.UDPConn
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

	dash *dashState

	routeCache atomic.Value

	sessionsMu sync.Mutex
	sessions   map[string]*agentSession

	probeOutboundMu      sync.Mutex
	probeOutboundTargets map[string]time.Time

	lastAgentConnectAt    time.Time
	lastAgentDisconnectAt time.Time

	dynamicRoutes    map[string]dynamicRouteEntry
	dynamicPortLow   int
	dynamicPortHigh  int
	pendingUpdateAcks map[string]chan *apitypes.RouteUpdateAck

	agentUDPAddr atomic.Value // stores netip.AddrPort
	agentUDPTime atomic.Int64 // unix nano
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

func (s *Server) nextClientID() string {
	id := atomic.AddUint64(&s.clientIDCounter, 1)
	return strconv.FormatUint(id, 36)
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
	Routes map[string]helloRoute `json:"routes"`
	Email  emailcfg.Config       `json:"email,omitempty"`
}

type ServerStatus struct {
	AgentConnected bool
}

type EmailRuntimeStatus struct {
	PublicInboundListening bool
	PublicInboundAddr      string
}

func (s *Server) Status() ServerStatus {
	s.mu.RLock()
	connected := s.agentTCP != nil
	s.mu.RUnlock()

	return ServerStatus{AgentConnected: connected}
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
	connected := s.agentTCP != nil
	lastAgentConnectAt := s.lastAgentConnectAt
	lastAgentDisconnectAt := s.lastAgentDisconnectAt
	s.mu.RUnlock()

	snap := s.dash.snapshot(now, connected)
	snap.Runtime = s.runtimeStats(lastAgentConnectAt, lastAgentDisconnectAt)
	return snap
}

type routeConfig struct {
	enabled     bool
	isEncrypted bool
}

func (s *Server) updateRouteCache() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	newCache := make(map[string]routeConfig)
	for _, rt := range effectiveRoutes(s.cfg, s.dynamicRoutes) {
		newCache[rt.Name] = routeConfig{
			enabled:     rt.IsEnabled(),
			isEncrypted: rt.IsEncrypted(),
		}
	}
	s.routeCache.Store(newCache)
}

func (s *Server) updateRouteCacheLocked() {
	newCache := make(map[string]routeConfig)
	for _, rt := range effectiveRoutes(s.cfg, s.dynamicRoutes) {
		newCache[rt.Name] = routeConfig{
			enabled:     rt.IsEnabled(),
			isEncrypted: rt.IsEncrypted(),
		}
	}
	s.routeCache.Store(newCache)
}

func (s *Server) getRouteConfig(name string) (routeConfig, bool) {
	cache, _ := s.routeCache.Load().(map[string]routeConfig)
	rc, ok := cache[name]
	return rc, ok
}

// isAllowedOutboundSMTPTarget validates that the resolved address is a
// permitted SMTP destination: standard SMTP ports only and no loopback,
// private, or link-local addresses.
func isAllowedOutboundSMTPTarget(addr *net.TCPAddr) bool {
	switch addr.Port {
	case smtpPortStandard, smtpPortSubmissionTLS, smtpPortSubmission:
		// allowed SMTP ports
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
		Routes: buildHelloRoutes(cfg, dynamicRoutes),
		Email:  emailcfg.Normalize(cfg.Email),
	}
}

func (s *Server) buildHelloPacket() (*protocol.Packet, error) {
	s.mu.RLock()
	cfg := s.cfg
	dr := s.dynamicRoutes
	s.mu.RUnlock()
	payload, err := json.Marshal(buildHelloPayload(cfg, dr))
	if err != nil {
		return nil, err
	}
	return &protocol.Packet{Type: protocol.TypeHello, Payload: payload}, nil
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
		// Implicit TLS – close silently; writing plaintext to a client
		// that expects TLS would cause "first record does not look like
		// a TLS handshake".
	}
	_ = conn.SetWriteDeadline(time.Time{})
}

func (s *Server) SetRouteEnabled(name string, enabled bool) bool {
	s.mu.Lock()
	for i, rt := range s.cfg.Routes {
		if rt.Name == name {
			val := enabled
			s.cfg.Routes[i].Enabled = &val
			cfg := s.cfg
			dr := s.dynamicRoutes
			agent := s.agentTCP
			s.mu.Unlock()

			s.updateRouteCache()

			if agent != nil {
				payload, err := json.Marshal(buildHelloPayload(cfg, dr))
				if err != nil {
					return false
				}
				helloPkt := &protocol.Packet{Type: protocol.TypeHello, Payload: payload}
				remoteAddr := agent.RemoteAddr().String()
				s.sessionsMu.Lock()
				if session, ok := s.sessions[remoteAddr]; ok {
					session.writeMu.Lock()
					agent.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
					protocol.WritePacket(agent, helloPkt)
					session.writeMu.Unlock()
				}
				s.sessionsMu.Unlock()
			}
			return true
		}
	}
	if dr, ok := s.dynamicRoutes[name]; ok {
		val := enabled
		dr.Route.Enabled = &val
		s.dynamicRoutes[name] = dr
		cfg := s.cfg
		drMap := s.dynamicRoutes
		agent := s.agentTCP
		s.mu.Unlock()

		s.updateRouteCache()

		if agent != nil {
			payload, err := json.Marshal(buildHelloPayload(cfg, drMap))
			if err != nil {
				return false
			}
			helloPkt := &protocol.Packet{Type: protocol.TypeHello, Payload: payload}
			remoteAddr := agent.RemoteAddr().String()
			s.sessionsMu.Lock()
			if session, ok := s.sessions[remoteAddr]; ok {
				session.writeMu.Lock()
				agent.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
				protocol.WritePacket(agent, helloPkt)
				session.writeMu.Unlock()
			}
			s.sessionsMu.Unlock()
		}
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
	if s.appStore == nil {
		return false
	}
	if err := s.appStore.SetApplicationEnabled(context.Background(), label, enabled); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	apps, err := s.appStore.ListApplications(context.Background())
	if err != nil {
		return true
	}
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
						ln, err := net.Listen("tcp", dr.Route.PublicAddr)
						if err == nil {
							s.publicTCP[route.RouteName] = ln
							if s.ctx != nil {
								s.wg.Add(1)
								go s.acceptPublicTCP(ln, route.RouteName)
							}
						}
					}
					if _, hasConn := s.publicUDP[route.RouteName]; !hasConn && (dr.Route.Proto == routeProtoUDP || dr.Route.Proto == routeProtoBoth) && strings.TrimSpace(dr.Route.PublicAddr) != "" {
						addr, err := net.ResolveUDPAddr("udp", dr.Route.PublicAddr)
						if err == nil {
							conn, err := net.ListenUDP("udp", addr)
							if err == nil {
								conn.SetReadBuffer(8 * 1024 * 1024)
								conn.SetWriteBuffer(8 * 1024 * 1024)
								s.publicUDP[route.RouteName] = conn
								if s.ctx != nil {
									s.wg.Add(1)
									go s.acceptPublicUDP(conn, route.RouteName)
								}
							}
						}
					}
				}
			}
		}
	}
	s.updateRouteCacheLocked()
	cfg := s.cfg
	dr := s.dynamicRoutes
	agent := s.agentTCP
	if agent != nil {
		helloPayload := buildHelloPayload(cfg, dr)
		helloPayloadBytes, err := json.Marshal(helloPayload)
		if err == nil {
			helloPkt := &protocol.Packet{Type: protocol.TypeHello, Payload: helloPayloadBytes}
			remoteAddr := agent.RemoteAddr().String()
			s.sessionsMu.Lock()
			if session, ok := s.sessions[remoteAddr]; ok {
				session.writeMu.Lock()
				agent.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
				protocol.WritePacket(agent, helloPkt)
				session.writeMu.Unlock()
			}
			s.sessionsMu.Unlock()
		}
	}
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
		delete(s.udpCiphers, route.RouteName)
	}
	s.updateRouteCacheLocked()
	agent := s.agentTCP
	cfg := s.cfg
	dr := s.dynamicRoutes
	s.mu.Unlock()

	if err := s.appStore.DeleteApplication(context.Background(), label); err != nil {
		return false
	}

	if agent != nil {
		helloPayload := buildHelloPayload(cfg, dr)
		helloPayloadBytes, err := json.Marshal(helloPayload)
		if err == nil {
			helloPkt := &protocol.Packet{Type: protocol.TypeHello, Payload: helloPayloadBytes}
			remoteAddr := agent.RemoteAddr().String()
			s.sessionsMu.Lock()
			if session, ok := s.sessions[remoteAddr]; ok {
				session.writeMu.Lock()
				agent.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
				protocol.WritePacket(agent, helloPkt)
				session.writeMu.Unlock()
			}
			s.sessionsMu.Unlock()
		}
	}
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
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(req)

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
}

func (s *Server) processRouteRequestLocked(req apitypes.RouteRequest) apitypes.RouteResponse {
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

	if req.Source == "api" && s.cfg.MaxDynamicRoutesPerAgent > 0 {
		dynamicCount := len(s.dynamicRoutes)
		if dynamicCount >= s.cfg.MaxDynamicRoutesPerAgent {
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

	if s.appStore != nil {
		if req.Source == "api" {
			app, err := s.appStore.GetApplication(context.Background(), req.Name)
			if err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to get application %s: %v", req.Name, err)
			} else if app == nil {
				app, err = s.appStore.CreateApplication(context.Background(), req.Name, "")
				if err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to create application %s: %v", req.Name, err)
				}
			}
			if app != nil {
				_, err := s.appStore.AddRoute(context.Background(), app.ID, appstore.AppRoute{
					RouteName:     rt.Name,
					Proto:         rt.Proto,
					PublicAddr:    rt.PublicAddr,
					LocalAddr:     rt.LocalAddr,
					Encrypted:     rt.IsEncrypted(),
					Domain:        rt.Domain,
					DomainEnabled: rt.IsDomainEnabled(),
					Enabled:       rt.IsEnabled(),
				})
				if err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to persist route %s: %v", rt.Name, err)
				}
			}
		} else {
			routes, err := s.appStore.ListRoutes(context.Background())
			if err == nil {
				var appID int64
				for _, r := range routes {
					if r.RouteName == rt.Name {
						appID = r.AppID
						break
					}
				}
				if appID == 0 {
					app, aerr := s.appStore.CreateApplication(context.Background(), rt.Name, "")
					if aerr != nil {
						logging.Global().Errorf(logging.CatTCP, "failed to create application for non-api route %s: %v", rt.Name, aerr)
					} else {
						appID = app.ID
					}
				}
				if appID != 0 {
					_, err = s.appStore.AddRoute(context.Background(), appID, appstore.AppRoute{
						RouteName:     rt.Name,
						Proto:         rt.Proto,
						PublicAddr:    rt.PublicAddr,
						LocalAddr:     rt.LocalAddr,
						Encrypted:     rt.IsEncrypted(),
						Domain:        rt.Domain,
						DomainEnabled: rt.IsDomainEnabled(),
						Enabled:       rt.IsEnabled(),
					})
					if err != nil {
						logging.Global().Errorf(logging.CatTCP, "failed to persist route %s: %v", rt.Name, err)
					}
				}
			}
		}
	}

	if rt.IsEncrypted() {
		key, err := crypto.DeriveKey(s.cfg.Token, s.cfg.EncryptionAlgorithm)
		if err == nil {
			s.derivedKeys[rt.Name] = key
			aead, _ := crypto.NewUDPCipher(key)
			if aead != nil {
				s.udpCiphers[rt.Name] = aead
			}
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
		if err == nil {
			conn, err := net.ListenUDP("udp", addr)
			if err == nil {
				conn.SetReadBuffer(8 * 1024 * 1024)
				conn.SetWriteBuffer(8 * 1024 * 1024)
				s.publicUDP[rt.Name] = conn
				if s.ctx != nil {
					s.wg.Add(1)
					go s.acceptPublicUDP(conn, rt.Name)
				}
			}
		}
	}

	s.updateRouteCacheLocked()

	cfg := s.cfg
	dr := s.dynamicRoutes
	agent := s.agentTCP
	if agent != nil {
		helloPayload := buildHelloPayload(cfg, dr)
		helloPayloadBytes, err := json.Marshal(helloPayload)
		if err == nil {
			helloPkt := &protocol.Packet{Type: protocol.TypeHello, Payload: helloPayloadBytes}
			remoteAddr := agent.RemoteAddr().String()
			s.sessionsMu.Lock()
			if session, ok := s.sessions[remoteAddr]; ok {
				session.writeMu.Lock()
				agent.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
				protocol.WritePacket(agent, helloPkt)
				session.writeMu.Unlock()
			}
			s.sessionsMu.Unlock()
		}
	}

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
	defer s.mu.Unlock()

	ack := s.processRouteConfirmLocked(confirm)

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
}

func (s *Server) processRouteConfirmLocked(confirm apitypes.RouteConfirm) apitypes.RouteAck {
	dr, ok := s.dynamicRoutes[confirm.Name]
	if !ok {
		return apitypes.RouteAck{RequestID: confirm.RequestID, Status: "failed", Name: confirm.Name, Error: "dynamic route not found"}
	}

	domain := normalizeHostname(confirm.Domain)
	if err := validateHostname(domain); err != nil {
		return apitypes.RouteAck{RequestID: confirm.RequestID, Status: "failed", Name: confirm.Name, Error: "invalid domain: " + err.Error()}
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

	if s.appStore != nil {
		if err := s.appStore.RemoveRoute(context.Background(), confirm.Name); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to remove old persisted route %s for confirm: %v", confirm.Name, err)
		}
		app, aerr := s.appStore.FindApplicationByRouteName(context.Background(), confirm.Name)
		if aerr != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to find application for confirmed route %s: %v", confirm.Name, aerr)
		} else if app != nil {
			_, err := s.appStore.AddRoute(context.Background(), app.ID, appstore.AppRoute{
				RouteName:     dr.Route.Name,
				Proto:         dr.Route.Proto,
				PublicAddr:    dr.Route.PublicAddr,
				LocalAddr:     dr.Route.LocalAddr,
				Encrypted:     dr.Route.IsEncrypted(),
				Domain:        domain,
				DomainEnabled: true,
				Enabled:       dr.Route.IsEnabled(),
			})
			if err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to persist confirmed route %s: %v", confirm.Name, err)
			}
		}
	}

	s.updateRouteCacheLocked()

	cfg := s.cfg
	drMap := s.dynamicRoutes
	agent := s.agentTCP
	if agent != nil {
		helloPayload := buildHelloPayload(cfg, drMap)
		helloPayloadBytes, err := json.Marshal(helloPayload)
		if err == nil {
			helloPkt := &protocol.Packet{Type: protocol.TypeHello, Payload: helloPayloadBytes}
			remoteAddr := agent.RemoteAddr().String()
			s.sessionsMu.Lock()
			if session, ok := s.sessions[remoteAddr]; ok {
				session.writeMu.Lock()
				agent.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
				protocol.WritePacket(agent, helloPkt)
				session.writeMu.Unlock()
			}
			s.sessionsMu.Unlock()
		}
	}

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
	defer s.mu.Unlock()

	ack := s.processRouteRemoveLocked(remove)

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
}

func (s *Server) processRouteRemoveLocked(remove apitypes.RouteRemove) apitypes.RouteRemoveAck {
	_, ok := s.dynamicRoutes[remove.Name]
	if !ok {
		return apitypes.RouteRemoveAck{Name: remove.Name, Error: "dynamic route not found"}
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
	delete(s.udpCiphers, remove.Name)

	if s.appStore != nil {
		if err := s.appStore.RemoveRoute(context.Background(), remove.Name); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to remove persisted route %s: %v", remove.Name, err)
		}
	}

	s.updateRouteCacheLocked()

	cfg := s.cfg
	dr := s.dynamicRoutes
	agent := s.agentTCP
	if agent != nil {
		helloPayload := buildHelloPayload(cfg, dr)
		helloPayloadBytes, err := json.Marshal(helloPayload)
		if err == nil {
			helloPkt := &protocol.Packet{Type: protocol.TypeHello, Payload: helloPayloadBytes}
			remoteAddr := agent.RemoteAddr().String()
			s.sessionsMu.Lock()
			if session, ok := s.sessions[remoteAddr]; ok {
				session.writeMu.Lock()
				agent.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
				protocol.WritePacket(agent, helloPkt)
				session.writeMu.Unlock()
			}
			s.sessionsMu.Unlock()
		}
	}

	return apitypes.RouteRemoveAck{Name: remove.Name, OK: true}
}

func (s *Server) handleRouteUpdate(conn net.Conn, session *agentSession, payload []byte) {
	var req apitypes.RouteUpdate
	if err := json.Unmarshal(payload, &req); err != nil {
		logging.Global().Errorf(logging.CatTCP, "failed to parse route update: %v", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ack := s.processRouteUpdateLocked(req)

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
}

func (s *Server) processRouteUpdateLocked(req apitypes.RouteUpdate) apitypes.RouteUpdateAck {
	dr, ok := s.dynamicRoutes[req.Name]
	if !ok {
		return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: "dynamic route not found"}
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
		oldLn, hasOldLn := s.publicTCP[req.Name]
		if hasOldLn {
			oldLn.Close()
			delete(s.publicTCP, req.Name)
		}
		oldConn, hasOldConn := s.publicUDP[req.Name]
		if hasOldConn {
			oldConn.Close()
			delete(s.publicUDP, req.Name)
		}
		dr.Route.PublicAddr = newAddr

		if dr.Route.Proto == routeProtoTCP || dr.Route.Proto == routeProtoBoth {
			ln, err := net.Listen("tcp", newAddr)
			if err != nil {
				return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "failed", Name: req.Name, Error: fmt.Sprintf("failed to listen on %s: %v", newAddr, err)}
			}
			s.publicTCP[req.Name] = ln
			s.wg.Add(1)
			go s.acceptPublicTCP(ln, req.Name)
		}
		if dr.Route.Proto == routeProtoUDP || dr.Route.Proto == routeProtoBoth {
			addr, err := net.ResolveUDPAddr("udp", newAddr)
			if err == nil {
				conn, err := net.ListenUDP("udp", addr)
				if err == nil {
					conn.SetReadBuffer(8 * 1024 * 1024)
					conn.SetWriteBuffer(8 * 1024 * 1024)
					s.publicUDP[req.Name] = conn
					s.wg.Add(1)
					go s.acceptPublicUDP(conn, req.Name)
				}
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
			key, err := crypto.DeriveKey(s.cfg.Token, s.cfg.EncryptionAlgorithm)
			if err == nil {
				s.derivedKeys[req.Name] = key
				aead, _ := crypto.NewUDPCipher(key)
				if aead != nil {
					s.udpCiphers[req.Name] = aead
				}
			}
		} else {
			delete(s.derivedKeys, req.Name)
			delete(s.udpCiphers, req.Name)
		}
	}

	s.dynamicRoutes[req.Name] = dr
	s.updateRouteCacheLocked()

	if s.appStore != nil {
		ctx := context.Background()
		if existing, err := s.appStore.GetRouteByRouteName(ctx, req.Name); err == nil && existing != nil {
			ar := appstore.AppRoute{
				AppID:         existing.AppID,
				RouteName:     dr.Route.Name,
				Proto:         dr.Route.Proto,
				PublicAddr:    dr.Route.PublicAddr,
				LocalAddr:     dr.Route.LocalAddr,
				Encrypted:     dr.Route.IsEncrypted(),
				Domain:        dr.Route.Domain,
				DomainEnabled: dr.Route.IsDomainEnabled(),
				Enabled:       dr.Route.IsEnabled(),
				CreatedAt:     existing.CreatedAt,
			}
			s.appStore.RemoveRoute(ctx, req.Name)
			s.appStore.AddRoute(ctx, existing.AppID, ar)
		}
	}

	s.pushHelloToAgentLocked()

	return apitypes.RouteUpdateAck{RequestID: req.RequestID, Status: "updated", Name: req.Name}
}

func (s *Server) pushHelloToAgentLocked() {
	agent := s.agentTCP
	if agent == nil {
		return
	}
	cfg := s.cfg
	dr := s.dynamicRoutes
	helloPayload := buildHelloPayload(cfg, dr)
	helloPayloadBytes, err := json.Marshal(helloPayload)
	if err != nil {
		return
	}
	helloPkt := &protocol.Packet{Type: protocol.TypeHello, Payload: helloPayloadBytes}
	remoteAddr := agent.RemoteAddr().String()
	s.sessionsMu.Lock()
	if session, ok := s.sessions[remoteAddr]; ok {
		session.writeMu.Lock()
		agent.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
		protocol.WritePacket(agent, helloPkt)
		session.writeMu.Unlock()
	}
	s.sessionsMu.Unlock()
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

	return &apitypes.RouteStats{
		Name:       found.Name,
		Proto:      found.Proto,
		PublicAddr: found.PublicAddr,
		LocalAddr:  found.LocalAddr,
		Domain:     found.Domain,
		Connected:  s.agentTCP != nil,
		Source:     source,
	}
}

func (s *Server) AllRouteStats() []apitypes.RouteStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	connected := s.agentTCP != nil
	stats := make([]apitypes.RouteStats, 0, len(allRoutes))
	for _, rt := range allRoutes {
		source := "config"
		if _, ok := s.dynamicRoutes[rt.Name]; ok {
			source = "dynamic"
		}
		stats = append(stats, apitypes.RouteStats{
			Name:       rt.Name,
			Proto:      rt.Proto,
			PublicAddr: rt.PublicAddr,
			LocalAddr:  rt.LocalAddr,
			Domain:     rt.Domain,
			Connected:  connected,
			Source:     source,
		})
	}
	return stats
}

func (s *Server) RunAgentNettest(ctx context.Context, req AgentNettestRequest) (AgentNettestResult, error) {
	s.mu.Lock()
	agent := s.agentTCP
	if agent == nil {
		s.mu.Unlock()
		return AgentNettestResult{}, fmt.Errorf("agent not connected")
	}
	remoteAddr := agent.RemoteAddr().String()
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
		s.sessionsMu.Lock()
		if session, ok := s.sessions[remoteAddr]; ok {
			session.writeMu.Lock()
			session.conn.SetWriteDeadline(time.Now().Add(writeDeadlineShort))
			err := protocol.WritePacket(session.conn, pkt)
			session.writeMu.Unlock()
			s.sessionsMu.Unlock()

			if err != nil {
				continue
			}
		} else {
			s.sessionsMu.Unlock()
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
		s.sessionsMu.Lock()
		if session, ok := s.sessions[remoteAddr]; ok {
			session.writeMu.Lock()
			session.conn.SetWriteDeadline(time.Now().Add(bwTestTimeout))
			session.writeMu.Unlock()
		}
		s.sessionsMu.Unlock()
		for i := 0; i < bwCount; i++ {
			if ctx.Err() != nil {
				break
			}
			payload := make([]byte, bwPayloadBytes)
			binary.BigEndian.PutUint64(payload, uint64(1000+i))
			pkt := &protocol.Packet{Type: protocol.TypePing, Payload: payload}

			s.sessionsMu.Lock()
			if session, ok := s.sessions[remoteAddr]; ok {
				session.writeMu.Lock()
				if err := protocol.WritePacket(session.conn, pkt); err != nil {
					session.writeMu.Unlock()
					s.sessionsMu.Unlock()
					break
				}
				session.writeMu.Unlock()
				s.sessionsMu.Unlock()
				bwSent++
				bytesSent += int64(bwPayloadBytes)
			} else {
				s.sessionsMu.Unlock()
				break
			}
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
	s.mu.Lock()
	agent := s.agentTCP
	if agent == nil {
		s.mu.Unlock()
		return protocol.EmailProbeResult{}, fmt.Errorf("agent not connected")
	}
	remoteAddr := agent.RemoteAddr().String()
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

	s.sessionsMu.Lock()
	if session, ok := s.sessions[remoteAddr]; ok {
		session.writeMu.Lock()
		session.conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
		err = protocol.WritePacket(session.conn, pkt)
		session.writeMu.Unlock()
		s.sessionsMu.Unlock()
		if err != nil {
			return protocol.EmailProbeResult{}, err
		}
	} else {
		s.sessionsMu.Unlock()
		return protocol.EmailProbeResult{}, fmt.Errorf("agent session unavailable")
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
		udpCiphers:           make(map[string]cipher.AEAD),
		publicTCP:            make(map[string]net.Listener),
		publicUDP:            make(map[string]*net.UDPConn),
		pendingTCP:           make(map[pendingTCPKey]*pendingTCPEntry),
		dash:                 newDashState(),
		sessions:             make(map[string]*agentSession),
		probeOutboundTargets: make(map[string]time.Time),
		maxConnsPerRoute:     defaultMaxConnsPerRoute,
		dynamicRoutes:        make(map[string]dynamicRouteEntry),
		pendingUpdateAcks:    make(map[string]chan *apitypes.RouteUpdateAck),
	}
	s.agentUDPAddr.Store(netip.AddrPort{})
	s.domains = newDomainManager(s)
	if strings.TrimSpace(cfg.DynamicPortRange) != "" {
		parts := strings.SplitN(strings.TrimSpace(cfg.DynamicPortRange), "-", 2)
		if len(parts) == 2 {
			s.dynamicPortLow, _ = strconv.Atoi(strings.TrimSpace(parts[0]))
			s.dynamicPortHigh, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
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
			key, err := crypto.DeriveKey(cfg.Token, cfg.EncryptionAlgorithm)
			if err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to derive key for route %s: %v", rt.Name, err)
			} else {
				s.derivedKeys[rt.Name] = key
				cipher, _ := crypto.NewUDPCipher(key)
				s.udpCiphers[rt.Name] = cipher
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
						key, err := crypto.DeriveKey(cfg.Token, cfg.EncryptionAlgorithm)
						if err == nil {
							s.derivedKeys[route.RouteName] = key
							aead, _ := crypto.NewUDPCipher(key)
							if aead != nil {
								s.udpCiphers[route.RouteName] = aead
							}
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
	s.udpDataConn.SetReadBuffer(8 * 1024 * 1024)
	s.udpDataConn.SetWriteBuffer(8 * 1024 * 1024)
	s.wg.Add(1)
	go s.acceptAgentUDP()

	for _, rt := range effectiveRoutes(s.cfg, s.dynamicRoutes) {
		if strings.TrimSpace(rt.PublicAddr) != "" && (rt.Proto == routeProtoTCP || rt.Proto == routeProtoBoth) {
			ln, err := net.Listen("tcp", rt.PublicAddr)
			if err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to listen on public tcp %s: %v", rt.PublicAddr, err)
				continue
			}
			s.publicTCP[rt.Name] = ln
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
			conn.SetReadBuffer(8 * 1024 * 1024)
			conn.SetWriteBuffer(8 * 1024 * 1024)
			s.publicUDP[rt.Name] = conn
			s.wg.Add(1)
			go s.acceptPublicUDP(conn, rt.Name)
		}
	}

	if err := s.startDomainGateway(); err != nil {
		return err
	}

	logging.Global().Infof(logging.CatSystem, "Server started on control=%s data=%s", s.cfg.ControlAddr, s.cfg.DataAddr)
	return nil
}

func (s *Server) Stop() {
	s.cancel()
	if s.controlLn != nil {
		s.controlLn.Close()
	}
	if s.dataLn != nil {
		s.dataLn.Close()
	}
	if s.udpDataConn != nil {
		s.udpDataConn.Close()
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
	for _, ln := range s.publicTCP {
		ln.Close()
	}
	for _, conn := range s.publicUDP {
		conn.Close()
	}
	s.wg.Wait()
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

		conn.SetDeadline(time.Now().Add(authDeadline))
		if err := crypto.AuthenticateServer(conn, s.cfg.Token); err != nil {
			logging.Global().Errorf(logging.CatTCP, "control auth failed from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}
		conn.SetDeadline(time.Time{})

		remoteAddr := conn.RemoteAddr().String()

		var oldSession *agentSession
		s.sessionsMu.Lock()
		if existing := s.sessions[remoteAddr]; existing != nil {
			oldSession = existing
		}
		sessionCtx, sessionCancel := context.WithCancel(s.ctx)
		session := &agentSession{
			conn:        conn,
			cancel:      sessionCancel,
			remoteAddr:  remoteAddr,
			connectTime: time.Now(),
		}
		s.sessions[remoteAddr] = session
		s.sessionsMu.Unlock()

		if oldSession != nil {
			logging.Global().Infof(logging.CatTCP, "Terminating previous session from %s", remoteAddr)
			if oldSession.cancel != nil {
				oldSession.cancel()
			}
			if oldSession.conn != nil {
				oldSession.conn.Close()
			}
		}

		s.mu.Lock()
		currentEpoch := s.agentEpoch + 1
		s.agentEpoch = currentEpoch
		s.agentTCP = conn
		s.agentUDP = netip.AddrPort{}
		s.agentUDPAt = time.Time{}
		s.lastAgentConnectAt = time.Now()
		s.abortPendingTCPLocked()
		s.mu.Unlock()

		logging.Global().Infof(logging.CatTCP, "Agent connected to control from %s", remoteAddr)

		helloPkt, err := s.buildHelloPacket()
		if err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to build HELLO packet: %v", err)
			conn.Close()
			continue
		}
		session.writeMu.Lock()
		conn.SetWriteDeadline(time.Now().Add(writeDeadlineStandard))
		if err := protocol.WritePacket(conn, helloPkt); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to send HELLO: %v", err)
			conn.Close()
			session.writeMu.Unlock()
			s.mu.Lock()
			if s.agentTCP == conn && s.agentEpoch == currentEpoch {
				s.agentTCP = nil
			}
			s.mu.Unlock()
			s.sessionsMu.Lock()
			delete(s.sessions, remoteAddr)
			s.sessionsMu.Unlock()
			continue
		}
		session.writeMu.Unlock()

		s.wg.Add(1)
		go func(c net.Conn, session *agentSession, remoteAddr string, epoch uint64) {
			defer s.wg.Done()
			defer func() {
				c.Close()
				s.sessionsMu.Lock()
				if s.sessions[remoteAddr] == session {
					delete(s.sessions, remoteAddr)
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
						s.mu.RLock()
						isAgent := s.agentTCP == c && s.agentEpoch == epoch
						s.mu.RUnlock()
						if isAgent {
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
						s.mu.RLock()
						isAgent := s.agentTCP == c && s.agentEpoch == epoch
						s.mu.RUnlock()
						if isAgent {
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

				c.SetReadDeadline(time.Now().Add(readDeadlineStandard))
				pkt, err := protocol.ReadPacket(c)
				if err != nil {
					break
				}
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

		s.mu.Lock()
		if s.agentTCP == c && s.agentEpoch == epoch {
			s.agentTCP = nil
			s.lastAgentDisconnectAt = time.Now()
			s.closeDomainProxyIdleConnections()
			s.abortPendingTCPLocked()
			logging.Global().Infof(logging.CatTCP, "Agent disconnected from control")
		}
		s.mu.Unlock()
		}(conn, session, remoteAddr, currentEpoch)
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

		handshakeDL := time.Now().Add(handshakeDeadline)
		conn.SetDeadline(handshakeDL)
		if err := crypto.AuthenticateServer(conn, s.cfg.Token); err != nil {
			logging.Global().Errorf(logging.CatTCP, "data auth failed from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}
		conn.SetReadDeadline(handshakeDL)

		var routeLen byte
		if err := binary.Read(conn, binary.BigEndian, &routeLen); err != nil {
			conn.Close()
			continue
		}
		routeBytes := make([]byte, routeLen)
		if _, err := io.ReadFull(conn, routeBytes); err != nil {
			conn.Close()
			continue
		}

		var clientLen byte
		if err := binary.Read(conn, binary.BigEndian, &clientLen); err != nil {
			conn.Close()
			continue
		}
		clientBytes := make([]byte, clientLen)
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

		rc, _ := s.getRouteConfig(routeName)
		isEncrypted := rc.isEncrypted

		if isEncrypted {
			key := s.derivedKeys[routeName]
			if key == nil {
				logging.Global().Errorf(logging.CatTCP, "failed to derive key for route %s: key is nil", routeName)
				conn.Close()
				continue
			}
			conn, err = crypto.WrapTCP(conn, key, false)
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
			conn.SetReadDeadline(time.Time{})
		}
		s.mu.Unlock()

		if ok {
			entry.deliver(conn)
		} else {
			conn.Close()
		}
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
		clientID := s.nextClientID()
		logging.Global().Infof(logging.CatTCP, "New public TCP connection route=%s client=%s", routeName, clientID)

		s.mu.RLock()
		agent := s.agentTCP
		epoch := s.agentEpoch
		s.mu.RUnlock()
		rc, ok := s.getRouteConfig(routeName)
		enabled := ok && rc.enabled

		if agent == nil || !enabled {
			<-sem
			if isEmailRoute(routeName) {
				logging.Global().Warnf(logging.CatTCP, "mail public connection rejected route=%s agentConnected=%v enabled=%v", routeName, agent != nil, enabled)
				writeMailRouteUnavailable(conn, routeName)
			}
			conn.Close()
			continue
		}

		remoteAddr := agent.RemoteAddr().String()

		entry := newPendingTCPEntry()
		pendingKey := makePendingTCPKey(routeName, clientID)
		s.mu.Lock()
		if s.agentEpoch != epoch {
			// Agent reconnected between capturing it and adding this
			// pending entry. The abort already ran so this entry would
			// be orphaned — reject immediately instead of hanging for
			// PairTimeout.
			s.mu.Unlock()
			<-sem
			logging.Global().Warnf(logging.CatTCP, "agent epoch changed, rejecting stale public TCP route=%s client=%s", routeName, clientID)
			writeMailRouteUnavailable(conn, routeName)
			conn.Close()
			continue
		}
		s.pendingTCP[pendingKey] = entry
		s.mu.Unlock()

		reqPkt := &protocol.Packet{
			Type:   protocol.TypeConnect,
			Route:  routeName,
			Client: clientID,
		}
		// Snapshot the session under the lock, then release it before any
		// network I/O so a slow agent recv side cannot serialize all public
		// accepts (or block control-plane registration on sessionsMu).
		s.sessionsMu.Lock()
		session, sessionOK := s.sessions[remoteAddr]
		s.sessionsMu.Unlock()
		if !sessionOK {
			<-sem
			logging.Global().Warnf(logging.CatTCP, "agent session unavailable for route=%s client=%s", routeName, clientID)
			writeMailRouteUnavailable(conn, routeName)
			conn.Close()
			s.mu.Lock()
			delete(s.pendingTCP, pendingKey)
			s.mu.Unlock()
			entry.cancel()
			continue
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

				countBytes := func(n int) {
					s.dash.addBytes(time.Now(), int64(n))
				}
				relay.ProxyWithIdleTimeout(&countingConn{Conn: c, onRead: countBytes}, &countingConn{Conn: agentConn, onRead: countBytes}, proxyIdleTimeout)

			case <-timer.C:
				// Race: delivery may have arrived at the exact moment the timer
				// fired. If a connection was already delivered, use it rather
				// than discarding a valid pairing.
				agentConn := entry.take()
				if agentConn != nil {
					logging.Global().Infof(logging.CatTCP, "paired public TCP route=%s client=%s (race recovery)", routeName, clientID)
					s.dash.addConn(time.Now())
					s.dash.incActive(routeName)
					defer s.dash.decActive(routeName)

					countBytes := func(n int) {
						s.dash.addBytes(time.Now(), int64(n))
					}
					relay.ProxyWithIdleTimeout(&countingConn{Conn: c, onRead: countBytes}, &countingConn{Conn: agentConn, onRead: countBytes}, proxyIdleTimeout)
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

type countingConn struct {
	net.Conn
	onRead func(int)
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.onRead != nil {
		c.onRead(n)
	}
	return n, err
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
	var pkt protocol.Packet

	var pendingBytes int64
	var pendingBytesTime time.Time
	const dashBatchInterval = 100 * time.Millisecond

	for {
		n, addr, err := s.udpDataConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}

		err = protocol.UnmarshalUDPTo(buf[:n], &pkt)
		if err != nil {
			continue
		}

		routeName := string([]byte(pkt.Route))
		clientID := string([]byte(pkt.Client))

		currentAddr, _ := s.agentUDPAddr.Load().(netip.AddrPort)
		if pkt.Type == protocol.TypeRegister {
			if !currentAddr.IsValid() || currentAddr != addr {
				s.agentUDPAddr.Store(addr)
				logging.Global().Infof(logging.CatUDP, "Agent UDP address registered: %s", addr.String())
			}
			now := time.Now().UnixNano()
			s.agentUDPTime.Store(now)
			s.mu.Lock()
			s.agentUDP = addr
			s.agentUDPAt = time.Unix(0, now)
			s.mu.Unlock()
		} else if !currentAddr.IsValid() || currentAddr != addr {
			s.agentUDPAddr.Store(addr)
			now := time.Now().UnixNano()
			s.agentUDPTime.Store(now)
			s.mu.Lock()
			s.agentUDP = addr
			s.agentUDPAt = time.Unix(0, now)
			s.mu.Unlock()
		}

		if pkt.Type == protocol.TypeRegister {
			continue
		}

		if pkt.Type == protocol.TypeData {
			s.mu.RLock()
			pubConn, ok := s.publicUDP[routeName]
			udpCipher := s.udpCiphers[routeName]
			s.mu.RUnlock()

			if !ok {
				continue
			}

			cache := s.routeCache.Load().(map[string]routeConfig)
			rc, ok := cache[routeName]
			if !ok {
				continue
			}

			payload := pkt.Payload
			if rc.isEncrypted {
				if udpCipher == nil {
					continue
				}
				decrypted, err := crypto.DecryptUDP(udpCipher, decryptBuf, payload)
				if err != nil {
					continue
				}
				payload = decrypted
			}

			clientAddrPort, err := netip.ParseAddrPort(clientID)
			if err != nil {
				continue
			}

			pendingBytes += int64(len(payload))
			if pendingBytesTime.IsZero() {
				pendingBytesTime = time.Now()
			} else if time.Since(pendingBytesTime) > dashBatchInterval {
				s.dash.addBytes(pendingBytesTime, pendingBytes)
				pendingBytes = 0
				pendingBytesTime = time.Time{}
			}
			pubConn.WriteToUDPAddrPort(payload, clientAddrPort)
		}
	}
}

func (s *Server) acceptPublicUDP(conn *net.UDPConn, routeName string) {
	defer s.wg.Done()
	defer conn.Close()

	buf := make([]byte, 65536)
	marshalBuf := make([]byte, 65536)
	encryptBuf := make([]byte, 65536)

	addrStrCache := make(map[netip.AddrPort]string)
	var pkt protocol.Packet

	var pendingBytes int64
	var pendingBytesTime time.Time
	const dashBatchInterval = 100 * time.Millisecond

	for {
		n, addr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}

		clientStr, ok := addrStrCache[addr]
		if !ok {
			clientStr = addr.String()
			if len(addrStrCache) > 10000 {
				addrStrCache = make(map[netip.AddrPort]string)
			}
			addrStrCache[addr] = clientStr
		}

		agentAddr, _ := s.agentUDPAddr.Load().(netip.AddrPort)
		agentUDPAt := time.Unix(0, s.agentUDPTime.Load())
		s.mu.RLock()
		udpCipher := s.udpCiphers[routeName]
		s.mu.RUnlock()

		if !agentAddr.IsValid() {
			continue
		}

		if !agentUDPAt.IsZero() && time.Since(agentUDPAt) > udpRegisterTimeout {
			s.mu.Lock()
			if !s.agentUDPAt.IsZero() && time.Since(s.agentUDPAt) > udpRegisterTimeout {
				logging.Global().Infof(logging.CatUDP, "Agent UDP address timed out after 60s inactivity")
				s.agentUDP = netip.AddrPort{}
			}
			s.mu.Unlock()
			continue
		}

		cache := s.routeCache.Load().(map[string]routeConfig)
		rc, ok := cache[routeName]
		if !ok || !agentAddr.IsValid() || !rc.enabled {
			continue
		}

		payload := buf[:n]
		if rc.isEncrypted {
			if udpCipher == nil {
				continue
			}
			encrypted, err := crypto.EncryptUDP(udpCipher, encryptBuf, payload)
			if err != nil {
				continue
			}
			payload = encrypted
		}

		pkt.Type = protocol.TypeData
		pkt.Route = routeName
		pkt.Client = clientStr
		pkt.Payload = payload

		data, err := protocol.MarshalUDP(&pkt, marshalBuf)
		if err != nil {
			continue
		}

		pendingBytes += int64(len(pkt.Payload))
		if pendingBytesTime.IsZero() {
			pendingBytesTime = time.Now()
		} else if time.Since(pendingBytesTime) > dashBatchInterval {
			s.dash.addBytes(pendingBytesTime, pendingBytes)
			pendingBytes = 0
			pendingBytesTime = time.Time{}
		}
		s.udpDataConn.WriteToUDPAddrPort(data, agentAddr)
	}
}
