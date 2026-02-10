package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hostit/server/internal/lineproto"
	"hostit/server/internal/udpproto"
	"hostit/shared/logging"
	"hostit/shared/udputil"
)

// Logger for tunnel operations - can be set externally
var log = logging.Global()

// SetLogger sets the logger for the tunnel package.
func SetLogger(l *logging.Logger) {
	log = l
}

var udpBufPool = sync.Pool{New: func() any {
	b := make([]byte, 64*1024)
	return &b
}}

// Default limits for pending connections (used when config values are not set)
const defaultMaxPendingConns = 10000
const defaultMaxPendingPerIP = 100

func tokensEqualCT(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type ServerStatus struct {
	AgentConnected bool
}

type Server struct {
	cfg ServerConfig
	st  *serverState
}

func NewServer(cfg ServerConfig) *Server {
	normalizeRoutes(&cfg)
	_ = EnsureUDPKeys(&cfg, time.Now())
	if cfg.PairTimeout == 0 {
		cfg.PairTimeout = 15 * time.Second
	}
	// Apply default limits if not configured (nil means use default, 0 means no limit)
	if cfg.MaxPendingConns == nil {
		v := defaultMaxPendingConns
		cfg.MaxPendingConns = &v
	}
	if cfg.MaxPendingPerIP == nil {
		v := defaultMaxPendingPerIP
		cfg.MaxPendingPerIP = &v
	}
	noDelay := make(map[string]bool, len(cfg.Routes))
	for _, rt := range cfg.Routes {
		if rt.TCPNoDelay == nil {
			noDelay[rt.Name] = true
		} else {
			noDelay[rt.Name] = *rt.TCPNoDelay
		}
	}

	st := &serverState{
		cfg:            cfg,
		pending:        map[string]pendingConn{},
		pendingByIP:    map[string]int{},
		publicUDP:      map[string]net.PacketConn{},
		dash:           newDashStateWithInterval(cfg.DashboardInterval),
		udpPublicJobs:  make(map[string]chan udpJob),
		errLast:        make(map[string]time.Time),
		udpStats:       udputil.NewSessionStats(1000, 5*time.Minute),
		encryptionNone: cfg.DisableUDPEncryption || strings.EqualFold(strings.TrimSpace(cfg.UDPEncryptionMode), "none"),
		resolvedAddrs:  make(map[string]*net.UDPAddr),
		noDelayByRoute: noDelay,
	}
	st.udpKeys = buildUDPKeySet(cfg)
	return &Server{cfg: cfg, st: st}
}

func buildUDPKeySet(cfg ServerConfig) udpproto.KeySet {
	mode := udpproto.NormalizeMode(cfg.UDPEncryptionMode)
	if cfg.DisableUDPEncryption {
		mode = udpproto.ModeNone
	}
	if mode == udpproto.ModeNone {
		ks, _ := udpproto.NewKeySet(mode, "", 0, nil, 0, nil)
		return ks
	}
	curSalt, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(cfg.UDPKeySaltB64))
	if err != nil {
		curSalt = nil
	}
	prevSalt, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(cfg.UDPPrevKeySaltB64))
	if err != nil {
		prevSalt = nil
	}
	ks, err := udpproto.NewKeySet(mode, strings.TrimSpace(cfg.Token), cfg.UDPKeyID, curSalt, cfg.UDPPrevKeyID, prevSalt)
	if err != nil {
		ks, _ = udpproto.NewKeySet(udpproto.ModeNone, "", 0, nil, 0, nil)
	}
	return ks
}

func (s *Server) Status() ServerStatus {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	return ServerStatus{AgentConnected: s.st.agentConn != nil}
}

func (s *Server) Dashboard(now time.Time) DashboardSnapshot {
	s.st.mu.Lock()
	agentConnected := s.st.agentConn != nil
	s.st.mu.Unlock()
	if s.st.dash == nil {
		return DashboardSnapshot{NowUnix: now.Unix(), AgentConnected: agentConnected}
	}
	snap := s.st.dash.snapshot(now, agentConnected)
	
	// Add UDP stats if available
	if s.st.udpStats != nil {
		summary := s.st.udpStats.Summary()
		snap.UDP = &UDPStats{
			PacketsIn:    int64(summary.GlobalStats.PacketsReceived),
			PacketsOut:   int64(summary.GlobalStats.PacketsSent),
			BytesIn:      int64(summary.GlobalStats.BytesReceived),
			BytesOut:     int64(summary.GlobalStats.BytesSent),
			ActiveRoutes: len(summary.ByRoute),
		}
	}
	
	return snap
}

func Serve(ctx context.Context, cfg ServerConfig) error {
	return NewServer(cfg).Run(ctx)
}

func (s *Server) Run(ctx context.Context) error {
	controlLn, err := listenControl(s.cfg)
	if err != nil {
		return fmt.Errorf("listen control: %w", err)
	}
	defer controlLn.Close()

	dataLn, err := listenDataTCP(s.cfg)
	if err != nil {
		return fmt.Errorf("listen data: %w", err)
	}
	defer dataLn.Close()

	var dataLnInsecure net.Listener
	if !s.cfg.DisableTLS {
		if addr := strings.TrimSpace(s.cfg.DataAddrInsecure); addr != "" {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen data insecure: %w", err)
			}
			dataLnInsecure = ln
			defer dataLnInsecure.Close()
		}
	}

	udpDataConn, err := net.ListenPacket("udp", s.cfg.DataAddr)
	if err != nil {
		return fmt.Errorf("listen data udp: %w", err)
	}
	if uc, ok := udpDataConn.(*net.UDPConn); ok {
		// Larger UDP buffers reduce drops/jitter for high-bitrate UDP workloads.
		_ = uc.SetReadBuffer(4 * 1024 * 1024)
		_ = uc.SetWriteBuffer(4 * 1024 * 1024)
	}
	defer udpDataConn.Close()

	type publicTCPListener struct {
		name string
		ln   net.Listener
	}
	publicTCP := make([]publicTCPListener, 0, len(s.cfg.Routes))
	for _, rt := range s.cfg.Routes {
		if !routeHasTCP(rt.Proto) {
			continue
		}
		ln, err := net.Listen("tcp", rt.PublicAddr)
		if err != nil {
			for _, x := range publicTCP {
				_ = x.ln.Close()
			}
			return fmt.Errorf("listen public tcp (%s=%s): %w", rt.Name, rt.PublicAddr, err)
		}
		publicTCP = append(publicTCP, publicTCPListener{name: rt.Name, ln: ln})
	}
	defer func() {
		for _, x := range publicTCP {
			_ = x.ln.Close()
		}
	}()

	type publicUDPListener struct {
		name string
		pc   net.PacketConn
	}
	publicUDP := make([]publicUDPListener, 0, len(s.cfg.Routes))
	for _, rt := range s.cfg.Routes {
		if !routeHasUDP(rt.Proto) {
			continue
		}
		pc, err := net.ListenPacket("udp", rt.PublicAddr)
		if err != nil {
			for _, x := range publicUDP {
				_ = x.pc.Close()
			}
			return fmt.Errorf("listen public udp (%s=%s): %w", rt.Name, rt.PublicAddr, err)
		}
		if uc, ok := pc.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(4 * 1024 * 1024)
			_ = uc.SetWriteBuffer(4 * 1024 * 1024)
		}
		publicUDP = append(publicUDP, publicUDPListener{name: rt.Name, pc: pc})
	}
	defer func() {
		for _, x := range publicUDP {
			_ = x.pc.Close()
		}
	}()

	st := s.st
	st.udpData = udpDataConn
	for _, x := range publicUDP {
		st.publicUDP[x.name] = x.pc
	}

	// Start pending connection cleaner
	go st.startPendingCleaner(ctx)

	go func() {
		<-ctx.Done()
		_ = controlLn.Close()
		_ = dataLn.Close()
		if dataLnInsecure != nil {
			_ = dataLnInsecure.Close()
		}
		_ = udpDataConn.Close()
		for _, x := range publicTCP {
			_ = x.ln.Close()
		}
		for _, x := range publicUDP {
			_ = x.pc.Close()
		}
		st.clearAgent(nil)
	}()

	errCh := make(chan error, 4+len(publicTCP)+len(publicUDP))
	go func() { errCh <- st.acceptControl(ctx, controlLn) }()
	go func() { errCh <- st.acceptData(ctx, dataLn) }()
	if dataLnInsecure != nil {
		go func() { errCh <- st.acceptData(ctx, dataLnInsecure) }()
	}
	go func() { errCh <- st.acceptAgentUDP(ctx) }()
	// Use parallel accept for high-core systems
	acceptWorkers := 1
	if numCPU := os.Getenv("HOSTIT_ACCEPT_WORKERS"); numCPU != "" {
		if n, err := strconv.Atoi(numCPU); err == nil && n > 1 && n <= 32 {
			acceptWorkers = n
		}
	}
	for _, x := range publicTCP {
		if acceptWorkers > 1 {
			go func(name string, l net.Listener) { errCh <- st.acceptPublicTCPParallel(ctx, l, name, acceptWorkers) }(x.name, x.ln)
		} else {
			go func(name string, l net.Listener) { errCh <- st.acceptPublicTCP(ctx, l, name) }(x.name, x.ln)
		}
	}
	for _, x := range publicUDP {
		go func(name string, pc net.PacketConn) { errCh <- st.acceptPublicUDP(ctx, pc, name) }(x.name, x.pc)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			if err == nil {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

func listenControl(cfg ServerConfig) (net.Listener, error) {
	return listenMaybeTLS(cfg, cfg.ControlAddr)
}

func listenDataTCP(cfg ServerConfig) (net.Listener, error) {
	return listenMaybeTLS(cfg, cfg.DataAddr)
}

func listenMaybeTLS(cfg ServerConfig, addr string) (net.Listener, error) {
	if cfg.DisableTLS {
		return net.Listen("tcp", addr)
	}
	certFile := strings.TrimSpace(cfg.TLSCertFile)
	keyFile := strings.TrimSpace(cfg.TLSKeyFile)
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("tls enabled but TLSCertFile/TLSKeyFile not set")
	}
	if _, err := os.Stat(certFile); err != nil {
		return nil, fmt.Errorf("tls cert file: %w", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		return nil, fmt.Errorf("tls key file: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls keypair: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	return tls.Listen("tcp", addr, tlsCfg)
}

type serverState struct {
	cfg     ServerConfig
	udpKeys udpproto.KeySet
	dash    *dashState

	errMu   sync.Mutex
	errLast map[string]time.Time

	mu            sync.Mutex
	agentConn     net.Conn
	agentProto    *lineproto.RW
	agentWriteMu  sync.Mutex
	udpData       net.PacketConn
	publicUDP     map[string]net.PacketConn

	// Lock-free agent UDP state (hot path — read on every packet)
	agentUDPAddr  atomic.Value // stores net.Addr (nil = not registered)
	agentUDPKeyID atomic.Uint32

	// Cached encryption mode (computed once at creation, avoids per-packet string ops)
	encryptionNone bool

	// Precomputed route properties (avoids linear scan per connection).
	noDelayByRoute map[string]bool

	pendingMu      sync.Mutex
	pending        map[string]pendingConn
	pendingByIP    map[string]int // track pending count per IP for DoS prevention

	// Parallelization structures
	udpAgentJobs  chan udpJob
	udpPublicJobs map[string]chan udpJob

	// UDP statistics
	udpStats *udputil.SessionStats

	// UDP drop counters (atomic, for diagnostics)
	udpAgentDrops  atomic.Int64
	udpPublicDrops atomic.Int64

	// Resolved-address cache for outbound UDP replies (avoids net.ResolveUDPAddr per packet).
	resolvedMu    sync.RWMutex
	resolvedAddrs map[string]*net.UDPAddr
}

const dashSystemRoute = "_system"

type udpJob struct {
	data   []byte
	len    int      // Actual data length (data may be from pool with larger capacity)
	addr   net.Addr
	bufPtr *[]byte  // Pool buffer to return after processing (nil if data was copied)
}

type pendingConn struct {
	ch        chan net.Conn
	routeName string
	createdAt time.Time
	remoteIP  string // for DoS tracking
}

func (st *serverState) hasAgent() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.agentConn != nil && st.agentProto != nil
}

func (st *serverState) agentWriteLinef(expectedConn net.Conn, format string, args ...any) error {
	st.agentWriteMu.Lock()
	defer st.agentWriteMu.Unlock()

	st.mu.Lock()
	conn := st.agentConn
	proto := st.agentProto
	st.mu.Unlock()

	if conn == nil || proto == nil {
		return errors.New("no agent connected")
	}
	if expectedConn != nil && conn != expectedConn {
		return errors.New("agent changed")
	}
	// Set a write deadline to prevent blocking indefinitely on slow/stalled connections.
	// This ensures NEW commands don't pile up waiting behind a stuck write.
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := proto.WriteLinef(format, args...)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// Cached env-var checks — evaluated once to avoid os.Getenv + string ops per call.
var (
	debugEnabledOnce     sync.Once
	debugEnabledVal      bool
	tracePairEnabledOnce sync.Once
	tracePairEnabledVal  bool
	traceUDPEnabledOnce  sync.Once
	traceUDPEnabledVal   bool
)

func envBool(names ...string) bool {
	for _, name := range names {
		v := strings.TrimSpace(os.Getenv(name))
		if v != "" && v != "0" {
			return true
		}
	}
	return false
}

func debugEnabled() bool {
	debugEnabledOnce.Do(func() { debugEnabledVal = envBool("HOSTIT_DEBUG", "PLAYIT_DEBUG") })
	return debugEnabledVal
}

func tracePairEnabled() bool {
	tracePairEnabledOnce.Do(func() { tracePairEnabledVal = envBool("HOSTIT_TRACE_PAIR", "PLAYIT_TRACE_PAIR") })
	return tracePairEnabledVal
}

func traceUDPEnabled() bool {
	traceUDPEnabledOnce.Do(func() { traceUDPEnabledVal = envBool("HOSTIT_TRACE_UDP", "PLAYIT_TRACE_UDP") })
	return traceUDPEnabledVal
}

func debugf(format string, args ...any) {
	if !debugEnabled() {
		return
	}
	log.Debugf(logging.CatSystem, format, args...)
}

func tracePairf(format string, args ...any) {
	if !tracePairEnabled() {
		return
	}
	log.Tracef(logging.CatPairing, format, args...)
}

func traceUDPf(format string, args ...any) {
	if !traceUDPEnabled() {
		return
	}
	log.Tracef(logging.CatUDP, format, args...)
}

func hostFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if ta, ok := addr.(*net.TCPAddr); ok {
		if ta.IP != nil {
			return ta.IP.String()
		}
		return ""
	}
	if ua, ok := addr.(*net.UDPAddr); ok {
		if ua.IP != nil {
			return ua.IP.String()
		}
		return ""
	}
	h, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return strings.TrimSpace(h)
	}
	return strings.TrimSpace(addr.String())
}

func (st *serverState) dashError(routeName, kind, remoteIP, connID, detail string) {
	if st == nil || st.dash == nil {
		return
	}
	r := strings.TrimSpace(routeName)
	if r == "" {
		r = dashSystemRoute
	}
	st.dash.addEvent(r, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: kind, RemoteIP: remoteIP, ConnID: connID, Detail: detail})
}

func (st *serverState) dashErrorRateLimited(routeName, kind, remoteIP, connID, detail string, minInterval time.Duration) {
	if st == nil {
		return
	}
	if minInterval <= 0 {
		st.dashError(routeName, kind, remoteIP, connID, detail)
		return
	}
	r := strings.TrimSpace(routeName)
	if r == "" {
		r = dashSystemRoute
	}
	key := r + "|" + strings.TrimSpace(kind)
	now := time.Now()
	st.errMu.Lock()
	last := st.errLast[key]
	if !last.IsZero() && now.Sub(last) < minInterval {
		st.errMu.Unlock()
		return
	}
	st.errLast[key] = now
	st.errMu.Unlock()
	st.dashError(r, kind, remoteIP, connID, detail)
}

func (st *serverState) routeTCPNoDelay(routeName string) bool {
	if v, ok := st.noDelayByRoute[routeName]; ok {
		return v
	}
	return true // default
}

func (st *serverState) acceptControl(ctx context.Context, ln net.Listener) error {
	backoff := 50 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && (ne.Temporary() || ne.Timeout()) {
				t := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					t.Stop()
					return nil
				case <-t.C:
				}
				if backoff < 1*time.Second {
					backoff *= 2
					if backoff > 1*time.Second {
						backoff = 1 * time.Second
					}
				}
				continue
			}
			st.dashError(dashSystemRoute, "error_accept_control", "", "", err.Error())
			return err
		}
		backoff = 50 * time.Millisecond
		go st.handleControlConn(ctx, conn)
	}
}

func (st *serverState) handleControlConn(ctx context.Context, conn net.Conn) {
	remoteIP := hostFromAddr(conn.RemoteAddr())
	setTCPKeepAlive(conn, 30*time.Second)
	// Control channel is latency-sensitive (NEW/CONN pairing, ROUTE updates).
	setTCPNoDelay(conn, true)
	setTCPQuickACK(conn, true)

	rw := lineproto.New(conn, conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := rw.ReadLine()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Debug(logging.CatControl, "control connection failed to read HELLO", logging.F(
			"remote_ip", remoteIP,
			"error", err,
		))
		st.dashError(dashSystemRoute, "error_agent_hello_read", remoteIP, "", err.Error())
		_ = rw.WriteLinef("ERR %s", "no hello")
		_ = conn.Close()
		return
	}
	cmd, rest := lineproto.Split2(line)
	if cmd != "HELLO" {
		log.Warn(logging.CatControl, "control connection sent invalid command", logging.F(
			"remote_ip", remoteIP,
			"expected", "HELLO",
			"got", cmd,
		))
		st.dashError(dashSystemRoute, "error_agent_bad_command", remoteIP, "", "expected HELLO, got "+cmd)
		_ = rw.WriteLinef("ERR %s", "expected HELLO")
		_ = conn.Close()
		return
	}
	expected := strings.TrimSpace(st.cfg.Token)
	if expected == "" {
		log.Error(logging.CatControl, "server token not configured")
		st.dashError(dashSystemRoute, "error_server_no_token", remoteIP, "", "server token not configured")
		_ = rw.WriteLinef("ERR %s", "server token not set")
		_ = conn.Close()
		return
	}
	if !tokensEqualCT(expected, rest) {
		log.Warn(logging.CatAuth, "agent authentication failed - bad token", logging.F(
			"remote_ip", remoteIP,
		))
		st.dashError(dashSystemRoute, "error_agent_bad_token", remoteIP, "", "authentication failed")
		_ = rw.WriteLinef("ERR %s", "bad token (agent token must match server token)")
		_ = conn.Close()
		return
	}

	// Check and close any existing agent connection BEFORE setting up the new one.
	// We don't set agentConn until AFTER READY is sent to avoid a race condition
	// where hasAgent() returns true but the agent isn't listening for NEW yet.
	st.mu.Lock()
	prevConn := st.agentConn
	if prevConn != nil {
		// Takeover: close the previous agent connection.
		log.Info(logging.CatControl, "agent reconnected, closing previous connection", logging.F(
			"remote_ip", remoteIP,
		))
		if st.dash != nil {
			st.dash.addEvent(dashSystemRoute, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "agent_reconnect", RemoteIP: remoteIP, Detail: "closing previous connection"})
		}
		_ = prevConn.Close()
		st.agentConn = nil
		st.agentProto = nil
		st.setAgentUDPAddr(nil)
		st.agentUDPKeyID.Store(0)
	}
	st.mu.Unlock()

	// Send all handshake messages BEFORE marking agent as connected.
	// This prevents a race where handlePublicConn sees hasAgent()==true
	// but the agent hasn't received READY and isn't listening for NEW yet.
	insec := strings.TrimSpace(st.cfg.DataAddrInsecure)
	if insec == "" {
		insec = "-"
	}
	// Write directly to conn since agentConn isn't set yet
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := rw.WriteLinef("OK %s %s", st.cfg.DataAddr, insec); err != nil {
		_ = conn.SetWriteDeadline(time.Time{})
		log.Error(logging.CatControl, "failed to send OK to agent", logging.F("error", err))
		st.dashError(dashSystemRoute, "error_agent_send_ok", remoteIP, "", err.Error())
		_ = conn.Close()
		return
	}
	mode := strings.TrimSpace(st.cfg.UDPEncryptionMode)
	if st.cfg.DisableUDPEncryption {
		mode = "none"
	}
	curSalt := strings.TrimSpace(st.cfg.UDPKeySaltB64)
	prevSalt := strings.TrimSpace(st.cfg.UDPPrevKeySaltB64)
	if curSalt == "" {
		curSalt = "-"
	}
	if prevSalt == "" {
		prevSalt = "-"
	}
	if err := rw.WriteLinef("UDPSEC %s %d %s %d %s", mode, st.cfg.UDPKeyID, curSalt, st.cfg.UDPPrevKeyID, prevSalt); err != nil {
		_ = conn.SetWriteDeadline(time.Time{})
		log.Error(logging.CatControl, "failed to send UDPSEC to agent", logging.F("error", err))
		st.dashError(dashSystemRoute, "error_agent_send_udpsec", remoteIP, "", err.Error())
		_ = conn.Close()
		return
	}
	for _, rt := range st.cfg.Routes {
		noDelay := true
		if rt.TCPNoDelay != nil {
			noDelay = *rt.TCPNoDelay
		}
		nd := 0
		if noDelay {
			nd = 1
		}
		useTLS := true
		if rt.TunnelTLS != nil {
			useTLS = *rt.TunnelTLS
		}
		tlsFlag := 0
		if useTLS {
			tlsFlag = 1
		}
		pc := 0
		if rt.Preconnect != nil {
			pc = *rt.Preconnect
		}
		if err := rw.WriteLinef("ROUTE %s %s %s nodelay=%d tls=%d preconnect=%d", rt.Name, rt.Proto, rt.PublicAddr, nd, tlsFlag, pc); err != nil {
			_ = conn.SetWriteDeadline(time.Time{})
			log.Error(logging.CatControl, "failed to send ROUTE to agent", logging.F("route", rt.Name, "error", err))
			st.dashError(dashSystemRoute, "error_agent_send_route", remoteIP, "", rt.Name+": "+err.Error())
			_ = conn.Close()
			return
		}
		log.Debug(logging.CatControl, "sent route to agent", logging.F(
			"route", rt.Name,
			"proto", rt.Proto,
			"public_addr", rt.PublicAddr,
		))
	}
	if err := rw.WriteLinef("READY"); err != nil {
		_ = conn.SetWriteDeadline(time.Time{})
		log.Error(logging.CatControl, "failed to send READY to agent", logging.F("error", err))
		st.dashError(dashSystemRoute, "error_agent_send_ready", remoteIP, "", err.Error())
		_ = conn.Close()
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// NOW mark the agent as connected - after READY is sent and agent is listening
	st.mu.Lock()
	st.agentConn = conn
	st.agentProto = rw
	st.mu.Unlock()

	log.Info(logging.CatControl, "agent connected and ready", logging.F(
		"remote_ip", remoteIP,
		"routes", len(st.cfg.Routes),
	))
	if st.dash != nil {
		st.dash.addEvent(dashSystemRoute, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "agent_connected", RemoteIP: remoteIP, Detail: fmt.Sprintf("%d routes", len(st.cfg.Routes))})
	}

	// Heartbeat: server pings agent periodically; agent replies with PONG.
	// A shorter deadAfter reduces the window where the server thinks an agent is
	// connected but it's actually gone — during that window every NEW command is
	// doomed to time out.
	const pingEvery = 15 * time.Second
	const deadAfter = 30 * time.Second
	lastSeen := atomic.Int64{}
	lastSeen.Store(time.Now().UnixNano())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(deadAfter))
			line, err := rw.ReadLine()
			if err != nil {
				st.dashError(dashSystemRoute, "agent_read_error", remoteIP, "", err.Error())
				return
			}
			lastSeen.Store(time.Now().UnixNano())
			cmd, rest := lineproto.Split2(line)
			switch cmd {
			case "PONG":
				// ok
			case "PING":
				_ = st.agentWriteLinef(conn, "PONG %s", rest)
			default:
				// ignore
			}
		}
	}()

	go func() {
		t := time.NewTicker(pingEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-t.C:
				ls := time.Unix(0, lastSeen.Load())
				if time.Since(ls) > deadAfter {
					st.dashError(dashSystemRoute, "agent_heartbeat_timeout", remoteIP, "", fmt.Sprintf("no response in %v", deadAfter))
					st.clearAgent(conn)
					_ = conn.Close()
					return
				}
				if err := st.agentWriteLinef(conn, "PING %s", newID()); err != nil {
					st.dashError(dashSystemRoute, "agent_ping_failed", remoteIP, "", err.Error())
					st.clearAgent(conn)
					_ = conn.Close()
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		if st.dash != nil {
			st.dash.addEvent(dashSystemRoute, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "agent_disconnect", RemoteIP: remoteIP, Detail: "server shutdown"})
		}
	case <-done:
		if st.dash != nil {
			st.dash.addEvent(dashSystemRoute, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "agent_disconnect", RemoteIP: remoteIP, Detail: "connection closed"})
		}
	}
	st.clearAgent(conn)
	_ = conn.Close()
}

func (st *serverState) clearAgent(conn net.Conn) {
	st.mu.Lock()
	if st.agentConn == nil {
		st.mu.Unlock()
		return
	}
	if conn != nil && st.agentConn != conn {
		st.mu.Unlock()
		return
	}
	_ = st.agentConn.Close()
	st.agentConn = nil
	st.agentProto = nil
	st.setAgentUDPAddr(nil)
	st.agentUDPKeyID.Store(0)
	st.mu.Unlock()

	// Drain all pending connections immediately so public clients get rejected
	// right away instead of waiting for PairTimeout. Without this, when the
	// agent drops, every in-flight public connection hangs until the 15s pair
	// timeout before getting rejected.
	st.drainAllPending()
}

// drainAllPending rejects every outstanding pending pairing. Called when the
// agent disconnects so public connections fail fast instead of timing out.
func (st *serverState) drainAllPending() {
	st.pendingMu.Lock()
	for id, pend := range st.pending {
		// Send nil to signal handlePublicConn that the pairing is dead.
		select {
		case pend.ch <- nil:
		default:
		}
		if pend.remoteIP != "" {
			st.pendingByIP[pend.remoteIP]--
			if st.pendingByIP[pend.remoteIP] <= 0 {
				delete(st.pendingByIP, pend.remoteIP)
			}
		}
		delete(st.pending, id)
	}
	st.pendingMu.Unlock()
}

func (st *serverState) acceptData(ctx context.Context, ln net.Listener) error {
	backoff := 50 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && (ne.Temporary() || ne.Timeout()) {
				t := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					t.Stop()
					return nil
				case <-t.C:
				}
				if backoff < 1*time.Second {
					backoff *= 2
					if backoff > 1*time.Second {
						backoff = 1 * time.Second
					}
				}
				continue
			}
			st.dashError(dashSystemRoute, "error_accept_data", "", "", err.Error())
			return err
		}
		backoff = 50 * time.Millisecond
		setTCPKeepAlive(conn, 30*time.Second)
		go st.handleDataConn(conn)
	}
}

func (st *serverState) handleDataConn(conn net.Conn) {
	rw := lineproto.New(conn, conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := rw.ReadLine()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		tracePairf("pair: data conn read failed from=%v err=%v", conn.RemoteAddr(), err)
		st.dashError(dashSystemRoute, "error_data_read", hostFromAddr(conn.RemoteAddr()), "", err.Error())
		_ = conn.Close()
		return
	}
	cmd, rest := lineproto.Split2(line)
	if cmd != "CONN" || rest == "" {
		tracePairf("pair: data conn invalid first line from=%v line=%q", conn.RemoteAddr(), line)
		st.dashError(dashSystemRoute, "error_data_invalid", hostFromAddr(conn.RemoteAddr()), "", line)
		_ = conn.Close()
		return
	}
	id := rest

	st.pendingMu.Lock()
	pend, ok := st.pending[id]
	if ok {
		delete(st.pending, id)
		if pend.remoteIP != "" {
			st.pendingByIP[pend.remoteIP]--
			if st.pendingByIP[pend.remoteIP] <= 0 {
				delete(st.pendingByIP, pend.remoteIP)
			}
		}
	}
	st.pendingMu.Unlock()
	if !ok {
		tracePairf("pair: CONN id=%s -> no pending match from=%v (closing)", id, conn.RemoteAddr())
		st.dashError(dashSystemRoute, "error_conn_no_pending", hostFromAddr(conn.RemoteAddr()), id, "")
		_ = conn.Close()
		return
	}
	tracePairf("pair: CONN id=%s -> matched route=%s from=%v", id, pend.routeName, conn.RemoteAddr())
	if tc := unwrapTCPConn(conn); tc != nil {
		_ = tc.SetReadBuffer(256 * 1024)
		_ = tc.SetWriteBuffer(256 * 1024)
	}
	if st.routeTCPNoDelay(pend.routeName) {
		setTCPNoDelay(conn, true)
		setTCPQuickACK(conn, true)
	}

	// Send PAIRED acknowledgment to the agent before forwarding the connection.
	// This confirms to the agent that the CONN was matched successfully.
	// Without this, the agent has no way to know whether its CONN write reached
	// a live server — a stale/dead pool connection would silently fail, leading
	// to the "sometimes it just doesn't work" pairing failures.
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("PAIRED\n"))
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		tracePairf("pair: PAIRED write failed id=%s from=%v err=%v", id, conn.RemoteAddr(), err)
		st.dashError(dashSystemRoute, "error_paired_write", hostFromAddr(conn.RemoteAddr()), id, err.Error())
		_ = conn.Close()
		return
	}

	select {
	case pend.ch <- conn:
		return
	default:
		_ = conn.Close()
		return
	}
}

func (st *serverState) acceptPublicTCP(ctx context.Context, ln net.Listener, routeName string) error {
	backoff := 50 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		clientConn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && (ne.Temporary() || ne.Timeout()) {
				t := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					t.Stop()
					return nil
				case <-t.C:
				}
				if backoff < 1*time.Second {
					backoff *= 2
					if backoff > 1*time.Second {
						backoff = 1 * time.Second
					}
				}
				continue
			}
			st.dashError(routeName, "error_accept_public_tcp", "", "", err.Error())
			return err
		}
		backoff = 50 * time.Millisecond
		setTCPKeepAlive(clientConn, 30*time.Second)
		if tc := unwrapTCPConn(clientConn); tc != nil {
			_ = tc.SetReadBuffer(256 * 1024)
			_ = tc.SetWriteBuffer(256 * 1024)
		}
		if st.routeTCPNoDelay(routeName) {
			setTCPNoDelay(clientConn, true)
			setTCPQuickACK(clientConn, true)
		}
		go st.handlePublicConn(ctx, clientConn, routeName)
	}
}

func (st *serverState) handlePublicConn(ctx context.Context, clientConn net.Conn, routeName string) {
	defer clientConn.Close()

	var remoteIP string
	if ra := clientConn.RemoteAddr(); ra != nil {
		remoteIP = ra.String()
		if h, _, err := net.SplitHostPort(remoteIP); err == nil {
			remoteIP = h
		}
	}

	start := time.Now()
	id := newID()
	if st.dash != nil {
		st.dash.incActive(routeName)
		st.dash.addConn(start)
		st.dash.addEvent(routeName, DashboardEvent{TimeUnix: start.Unix(), Kind: "connect", RemoteIP: remoteIP, ConnID: id})
		defer st.dash.decActive(routeName)
	}

	if !st.hasAgent() {
		log.Warn(logging.CatPairing, "public connection rejected: no agent connected", logging.F(
			"route", routeName,
			"remote_ip", remoteIP,
			"conn_id", id,
		))
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "reject_no_agent", RemoteIP: remoteIP, ConnID: id})
		}
		return
	}

	ch := make(chan net.Conn, 1)
	st.pendingMu.Lock()
	// DoS protection: limit total pending and per-IP pending connections
	// A config value of 0 means no limit (infinity)
	maxConns := *st.cfg.MaxPendingConns
	maxPerIP := *st.cfg.MaxPendingPerIP
	if maxConns > 0 && len(st.pending) >= maxConns {
		st.pendingMu.Unlock()
		log.Warn(logging.CatPairing, "connection rejected: max pending connections reached", logging.F(
			"route", routeName,
			"remote_ip", remoteIP,
		))
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "reject_max_pending", RemoteIP: remoteIP, ConnID: id})
		}
		return
	}
	if maxPerIP > 0 && st.pendingByIP[remoteIP] >= maxPerIP {
		st.pendingMu.Unlock()
		log.Warn(logging.CatPairing, "connection rejected: max pending per IP reached", logging.F(
			"route", routeName,
			"remote_ip", remoteIP,
		))
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "reject_rate_limit", RemoteIP: remoteIP, ConnID: id})
		}
		return
	}
	st.pending[id] = pendingConn{ch: ch, routeName: routeName, createdAt: start, remoteIP: remoteIP}
	st.pendingByIP[remoteIP]++
	st.pendingMu.Unlock()
	debugf("tunnel: NEW id=%s route=%s", id, routeName)

	// Send NEW command synchronously BEFORE starting the timeout.
	// This ensures the agent receives the command immediately and the full
	// PairTimeout is available for the agent to dial back.
	if err := st.agentWriteLinef(nil, "NEW %s %s", id, routeName); err != nil {
		log.Error(logging.CatPairing, "NEW command write failed", logging.F(
			"conn_id", id,
			"route", routeName,
			"error", err,
		))
		st.dashError(routeName, "error_new_send", remoteIP, id, err.Error())
		st.pendingMu.Lock()
		delete(st.pending, id)
		st.pendingByIP[remoteIP]--
		if st.pendingByIP[remoteIP] <= 0 {
			delete(st.pendingByIP, remoteIP)
		}
		st.pendingMu.Unlock()
		return
	}
	tracePairf("pair: sent NEW id=%s route=%s", id, routeName)

	timeout := time.NewTimer(st.cfg.PairTimeout)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return
	case agentConn := <-ch:
		if agentConn == nil {
			return
		}
		// Stop the timeout promptly so it doesn't fire during a long-lived pipe.
		timeout.Stop()
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "paired", RemoteIP: remoteIP, ConnID: id})
		}
		a2b, b2a := bidirPipeCount(clientConn, agentConn)
		if st.dash != nil {
			bytes := a2b + b2a
			st.dash.addBytes(time.Now(), bytes)
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "disconnect", RemoteIP: remoteIP, ConnID: id, Bytes: bytes, DurationMS: time.Since(start).Milliseconds()})
		}
	case <-timeout.C:
		debugf("tunnel: pair timeout id=%s route=%s after=%s", id, routeName, st.cfg.PairTimeout)
		log.Warn(logging.CatPairing, "pair timeout waiting for agent data connection", logging.F(
			"route", routeName,
			"remote_ip", remoteIP,
			"conn_id", id,
			"timeout", st.cfg.PairTimeout.String(),
		))
		st.pendingMu.Lock()
		delete(st.pending, id)
		st.pendingByIP[remoteIP]--
		if st.pendingByIP[remoteIP] <= 0 {
			delete(st.pendingByIP, remoteIP)
		}
		st.pendingMu.Unlock()
		// Drain any late-arriving matched connection to prevent leaks.
		// This can happen if handleDataConn matched and sent PAIRED just as
		// the timeout fired.
		select {
		case late := <-ch:
			if late != nil {
				_ = late.Close()
			}
		default:
		}
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "pair_timeout", RemoteIP: remoteIP, ConnID: id, Detail: st.cfg.PairTimeout.String()})
		}
		return
	}
}

func (st *serverState) getAgentProto() *lineproto.RW {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.agentProto
}

// addrHolder wraps net.Addr for atomic.Value storage (which cannot store nil directly).
type addrHolder struct{ addr net.Addr }

func (st *serverState) getAgentUDPAddr() net.Addr {
	v := st.agentUDPAddr.Load()
	if v == nil {
		return nil
	}
	return v.(addrHolder).addr
}

func (st *serverState) getAgentUDPKeyID() uint32 {
	return st.agentUDPKeyID.Load()
}

func (st *serverState) setAgentUDPAddr(addr net.Addr) {
	st.agentUDPAddr.Store(addrHolder{addr})
}

func (st *serverState) setAgentUDPKeyID(id uint32) {
	st.agentUDPKeyID.Store(id)
}

func (st *serverState) acceptAgentUDP(ctx context.Context) error {
	pc := st.udpData
	if pc == nil {
		return nil
	}

	// Determine worker count from environment or default to NumCPU
	workers := runtime.NumCPU()
	if workers < 4 {
		workers = 4
	}
	if numWorkers := os.Getenv("HOSTIT_UDP_WORKERS"); numWorkers != "" {
		if n, err := strconv.Atoi(numWorkers); err == nil && n > 0 && n <= 64 {
			workers = n
		}
	}

	// Large buffer to absorb bursts without dropping packets.
	const jobBufSize = 4096
	jobs := make(chan udpJob, jobBufSize)
	st.udpAgentJobs = jobs

	// Start worker pool
	for i := 0; i < workers; i++ {
		go st.udpAgentWorker(ctx, jobs)
	}

	// Periodic drop-rate logger
	go func() {
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		var prevDrops int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				d := st.udpAgentDrops.Load()
				if d > prevDrops {
					log.Warnf(logging.CatUDP, "UDP agent queue drops: %d total (%d new)", d, d-prevDrops)
				}
				prevDrops = d
			}
		}
	}()

	// Single reader distributes packets to workers
	backoff := 50 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			close(jobs)
			return nil
		default:
		}
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			udpBufPool.Put(bufPtr)
			if errors.Is(err, net.ErrClosed) {
				close(jobs)
				return nil
			}
			if ne, ok := err.(net.Error); ok && (ne.Temporary() || ne.Timeout()) {
				t := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					t.Stop()
					close(jobs)
					return nil
				case <-t.C:
				}
				if backoff < 1*time.Second {
					backoff *= 2
					if backoff > 1*time.Second {
						backoff = 1 * time.Second
					}
				}
				continue
			}
			st.dashError(dashSystemRoute, "error_accept_agent_udp", hostFromAddr(addr), "", err.Error())
			close(jobs)
			return err
		}
		backoff = 50 * time.Millisecond

		// Pass pool buffer directly to worker - worker returns it after processing
		select {
		case jobs <- udpJob{data: buf, len: n, addr: addr, bufPtr: bufPtr}:
		default:
			// Drop packet if workers overwhelmed, return buffer to pool
			st.udpAgentDrops.Add(1)
			udpBufPool.Put(bufPtr)
		}
	}
}

// resolveUDP caches resolved UDP addresses to avoid net.ResolveUDPAddr per packet.
func (st *serverState) resolveUDP(addr string) (*net.UDPAddr, error) {
	st.resolvedMu.RLock()
	ua, ok := st.resolvedAddrs[addr]
	st.resolvedMu.RUnlock()
	if ok {
		return ua, nil
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	st.resolvedMu.Lock()
	// Cap cache size to prevent unbounded memory growth.
	if len(st.resolvedAddrs) < 100000 {
		st.resolvedAddrs[addr] = ua
	}
	st.resolvedMu.Unlock()
	return ua, nil
}

func (st *serverState) udpAgentWorker(ctx context.Context, jobs <-chan udpJob) {
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-jobs:
			if !ok {
				return
			}
			pkt := job.data
			if job.len > 0 && job.len < len(pkt) {
				pkt = pkt[:job.len]
			}
			st.processAgentUDPPacket(pkt, job.addr)
			// Return buffer to pool after processing
			if job.bufPtr != nil {
				udpBufPool.Put(job.bufPtr)
			}
		}
	}
}

func (st *serverState) processAgentUDPPacket(pkt []byte, addr net.Addr) {
	if len(pkt) == 0 {
		return
	}
	encNone := st.encryptionNone
	switch pkt[0] {
	case udpproto.MsgReg:
		if !encNone {
			return
		}
		tok, ok := udpproto.DecodeReg(pkt)
		if !ok {
			traceUDPf("udp: REG decode failed from=%v", addr)
			st.dashErrorRateLimited(dashSystemRoute, "error_udp_reg_decode", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		expected := strings.TrimSpace(st.cfg.Token)
		if expected != "" && !tokensEqualCT(expected, tok) {
			traceUDPf("udp: REG token mismatch from=%v", addr)
			st.dashErrorRateLimited(dashSystemRoute, "error_udp_reg_token", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		if st.getAgentProto() == nil {
			return
		}
		oldAddr := st.getAgentUDPAddr()
		st.setAgentUDPAddr(addr)
		st.setAgentUDPKeyID(0)
		if oldAddr == nil || oldAddr.String() != addr.String() {
			log.Infof(logging.CatUDP, "agent UDP registered addr=%v mode=plaintext", addr)
		}
	case udpproto.MsgRegEnc2:
		if encNone {
			return
		}
		expected := strings.TrimSpace(st.cfg.Token)
		if expected == "" {
			return
		}
		kid, ok := udpproto.DecodeRegEnc2(st.udpKeys, expected, pkt)
		if !ok {
			traceUDPf("udp: REGEnc2 decode failed from=%v", addr)
			st.dashErrorRateLimited(dashSystemRoute, "error_udp_regenc2_decode", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		if st.getAgentProto() == nil {
			return
		}
		oldAddr := st.getAgentUDPAddr()
		st.setAgentUDPAddr(addr)
		st.setAgentUDPKeyID(kid)
		if oldAddr == nil || oldAddr.String() != addr.String() {
			log.Infof(logging.CatUDP, "agent UDP registered addr=%v mode=encrypted keyID=%d", addr, kid)
		}
	case udpproto.MsgData:
		if !encNone {
			return
		}
		route, client, payload, ok := udpproto.DecodeData(pkt)
		if !ok {
			traceUDPf("udp: DATA decode failed from=%v", addr)
			st.dashErrorRateLimited(dashSystemRoute, "error_udp_data_decode", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		agent := st.getAgentUDPAddr()
		if agent == nil || agent.String() != addr.String() {
			return
		}
		pc2 := st.publicUDP[route]
		if pc2 == nil {
			traceUDPf("udp: DATA unknown route=%s from=%v", route, addr)
			st.dashErrorRateLimited(route, "error_udp_unknown_route", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		ua, err := st.resolveUDP(client)
		if err != nil {
			traceUDPf("udp: DATA bad client addr=%q route=%s err=%v", client, route, err)
			st.dashErrorRateLimited(route, "error_udp_bad_client", hostFromAddr(addr), client, err.Error(), 1*time.Second)
			return
		}
		if _, err := pc2.WriteTo(payload, ua); err != nil {
			traceUDPf("udp: DATA writeTo failed route=%s to=%v err=%v", route, ua, err)
			st.dashErrorRateLimited(route, "error_udp_write_public", hostFromAddr(ua), client, err.Error(), 1*time.Second)
		} else if st.dash != nil {
			st.dash.addBytes(time.Now(), int64(len(payload)))
		}
	case udpproto.MsgDataEnc2:
		if encNone {
			return
		}
		route, client, payload, _, ok := udpproto.DecodeDataEnc2(st.udpKeys, pkt)
		if !ok {
			traceUDPf("udp: DATAEnc2 decode failed from=%v", addr)
			st.dashErrorRateLimited(dashSystemRoute, "error_udp_dataenc2_decode", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		agent := st.getAgentUDPAddr()
		if agent == nil || agent.String() != addr.String() {
			return
		}
		pc2 := st.publicUDP[route]
		if pc2 == nil {
			traceUDPf("udp: DATAEnc2 unknown route=%s from=%v", route, addr)
			st.dashErrorRateLimited(route, "error_udp_unknown_route", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		ua, err := st.resolveUDP(client)
		if err != nil {
			traceUDPf("udp: DATAEnc2 bad client addr=%q route=%s err=%v", client, route, err)
			st.dashErrorRateLimited(route, "error_udp_bad_client", hostFromAddr(addr), client, err.Error(), 1*time.Second)
			return
		}
		if _, err := pc2.WriteTo(payload, ua); err != nil {
			traceUDPf("udp: DATAEnc2 writeTo failed route=%s to=%v err=%v", route, ua, err)
			st.dashErrorRateLimited(route, "error_udp_write_public", hostFromAddr(ua), client, err.Error(), 1*time.Second)
		} else if st.dash != nil {
			st.dash.addBytes(time.Now(), int64(len(payload)))
		}
	}
}

func (st *serverState) acceptPublicUDP(ctx context.Context, pc net.PacketConn, routeName string) error {
	// Determine worker count
	workers := runtime.NumCPU()
	if workers < 4 {
		workers = 4
	}
	if numWorkers := os.Getenv("HOSTIT_UDP_WORKERS"); numWorkers != "" {
		if n, err := strconv.Atoi(numWorkers); err == nil && n > 0 && n <= 64 {
			workers = n
		}
	}

	// Large buffer to absorb bursts without dropping packets.
	const jobBufSize = 4096
	jobs := make(chan udpJob, jobBufSize)
	st.mu.Lock()
	if st.udpPublicJobs == nil {
		st.udpPublicJobs = make(map[string]chan udpJob)
	}
	st.udpPublicJobs[routeName] = jobs
	st.mu.Unlock()

	// Start worker pool
	for i := 0; i < workers; i++ {
		go st.udpPublicWorker(ctx, jobs, routeName)
	}

	// Periodic drop-rate logger
	go func() {
		tick := time.NewTicker(10 * time.Second)
		defer tick.Stop()
		var prevDrops int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				d := st.udpPublicDrops.Load()
				if d > prevDrops {
					log.Warnf(logging.CatUDP, "UDP public queue drops (route=%s): %d total (%d new)", routeName, d, d-prevDrops)
				}
				prevDrops = d
			}
		}
	}()

	// Single reader distributes packets to workers
	backoff := 50 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			close(jobs)
			return nil
		default:
		}
		bufPtr := udpBufPool.Get().(*[]byte)
		buf := *bufPtr
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			udpBufPool.Put(bufPtr)
			if errors.Is(err, net.ErrClosed) {
				close(jobs)
				return nil
			}
			if ne, ok := err.(net.Error); ok && (ne.Temporary() || ne.Timeout()) {
				t := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					t.Stop()
					close(jobs)
					return nil
				case <-t.C:
				}
				if backoff < 1*time.Second {
					backoff *= 2
					if backoff > 1*time.Second {
						backoff = 1 * time.Second
					}
				}
				continue
			}
			st.dashError(routeName, "error_accept_public_udp", "", "", err.Error())
			close(jobs)
			return err
		}
		backoff = 50 * time.Millisecond

		// Pass pool buffer directly to worker - worker returns it after processing
		select {
		case jobs <- udpJob{data: buf, len: n, addr: clientAddr, bufPtr: bufPtr}:
		default:
			// Drop if workers overwhelmed, return buffer to pool
			st.udpPublicDrops.Add(1)
			udpBufPool.Put(bufPtr)
		}
	}
}

func (st *serverState) udpPublicWorker(ctx context.Context, jobs <-chan udpJob, routeName string) {
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-jobs:
			if !ok {
				return
			}
			pkt := job.data
			if job.len > 0 && job.len < len(pkt) {
				pkt = pkt[:job.len]
			}
			st.processPublicUDPPacket(pkt, job.addr, routeName)
			// Return buffer to pool after processing
			if job.bufPtr != nil {
				udpBufPool.Put(job.bufPtr)
			}
		}
	}
}

func (st *serverState) processPublicUDPPacket(pkt []byte, clientAddr net.Addr, routeName string) {
	agent := st.getAgentUDPAddr()
	if agent == nil {
		st.dashErrorRateLimited(routeName, "error_udp_no_agent", "", "", "", 1*time.Second)
		return
	}

	now := time.Now()
	
	// Track UDP session stats
	if st.udpStats != nil {
		clientIP := hostFromAddr(clientAddr)
		sessionID := routeName + ":" + clientIP
		info := st.udpStats.GetOrCreate(sessionID, routeName, clientIP, "")
		st.udpStats.RecordReceive(sessionID, len(pkt))
		// Log UDP client connections to dashboard (first-seen events)
		if st.dash != nil {
			if info.CreatedAt.Equal(info.LastActivityTime()) || info.Stats.Snapshot().PacketsReceived <= 1 {
				st.dash.addConn(now)
				st.dash.addEvent(routeName, DashboardEvent{TimeUnix: now.Unix(), Kind: "udp_session", RemoteIP: clientIP, Detail: "new UDP client"})
			}
		}
	}
	
	var msg []byte
	clientAddrStr := clientAddr.String()
	if st.encryptionNone || !st.udpKeys.Enabled() {
		msg = udpproto.EncodeData(routeName, clientAddrStr, pkt)
	} else {
		kid := st.getAgentUDPKeyID()
		if kid == 0 {
			kid = st.cfg.UDPKeyID
		}
		msg = udpproto.EncodeDataEnc2ForKeyID(st.udpKeys, kid, routeName, clientAddrStr, pkt)
	}
	if _, err := st.udpData.WriteTo(msg, agent); err != nil {
		st.dashErrorRateLimited(routeName, "error_udp_write_agent", hostFromAddr(agent), "", err.Error(), 1*time.Second)
		log.Warnf(logging.CatUDP, "UDP write to agent failed route=%s: %v", routeName, err)
	} else if st.dash != nil {
		// Track UDP bytes for bandwidth graph
		st.dash.addBytes(now, int64(len(pkt)))
	}
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func setTCPKeepAlive(conn net.Conn, period time.Duration) {
	tc := unwrapTCPConn(conn)
	if tc == nil {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(period)
}

func unwrapTCPConn(conn net.Conn) *net.TCPConn {
	if conn == nil {
		return nil
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc
	}
	if nc, ok := conn.(interface{ NetConn() net.Conn }); ok {
		return unwrapTCPConn(nc.NetConn())
	}
	return nil
}

func setTCPNoDelay(conn net.Conn, on bool) {
	tc := unwrapTCPConn(conn)
	if tc == nil {
		return
	}
	_ = tc.SetNoDelay(on)
}

func (st *serverState) startPendingCleaner(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st.cleanupOldPending(time.Now().Add(-30 * time.Second))
		}
	}
}

func (st *serverState) cleanupOldPending(cutoff time.Time) {
	st.pendingMu.Lock()
	var toDelete []string
	for id, pend := range st.pending {
		if pend.createdAt.Before(cutoff) {
			toDelete = append(toDelete, id)
			// Send nil to signal rejection rather than close(), which could
			// race with handleDataConn's send and panic.
			select {
			case pend.ch <- nil:
			default:
			}
		}
	}
	for _, id := range toDelete {
		pend := st.pending[id]
		if pend.remoteIP != "" {
			st.pendingByIP[pend.remoteIP]--
			if st.pendingByIP[pend.remoteIP] <= 0 {
				delete(st.pendingByIP, pend.remoteIP)
			}
		}
		delete(st.pending, id)
	}
	st.pendingMu.Unlock()
}

func (st *serverState) acceptPublicTCPParallel(ctx context.Context, ln net.Listener, routeName string, workers int) error {
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			errCh <- st.acceptPublicTCP(ctx, ln, routeName)
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}
