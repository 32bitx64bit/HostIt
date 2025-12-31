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
	"log"
	mathrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hostit/server/internal/lineproto"
	"hostit/server/internal/udpproto"
)

var udpBufPool = sync.Pool{New: func() any {
	b := make([]byte, 64*1024)
	return &b
}}

var idSource = mathrand.NewSource(time.Now().UnixNano())
var idMu sync.Mutex

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
		cfg.PairTimeout = 10 * time.Second
	}
	st := &serverState{
		cfg:           cfg,
		pending:       map[string]pendingConn{},
		publicUDP:     map[string]net.PacketConn{},
		dash:          newDashState(),
		udpPublicJobs: make(map[string]chan udpJob),
	}
	st.udpKeys = buildUDPKeySet(cfg)
	st.newBatcher = &newCommandBatcher{
		flush: make(chan struct{}, 1),
		timer: time.NewTimer(time.Hour),
		st:    st,
	}
	st.newBatcher.timer.Stop()
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
	return s.st.dash.snapshot(now, agentConnected)
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

	// Start NEW command batcher
	st.newBatcher.start(ctx)

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

	mu            sync.Mutex
	agentConn     net.Conn
	agentProto    *lineproto.RW
	agentWriteMu  sync.Mutex
	agentUDPAddr  net.Addr
	agentUDPKeyID uint32
	udpData       net.PacketConn
	publicUDP     map[string]net.PacketConn

	pendingMu sync.Mutex
	pending   map[string]pendingConn

	// Parallelization structures
	newBatcher    *newCommandBatcher
	udpAgentJobs  chan udpJob
	udpPublicJobs map[string]chan udpJob
}

type udpJob struct {
	data []byte
	addr net.Addr
}

type newCommandBatcher struct {
	mu      sync.Mutex
	pending []newCommand
	timer   *time.Timer
	flush   chan struct{}
	st      *serverState
}

type newCommand struct {
	id    string
	route string
}

type pendingConn struct {
	ch        chan net.Conn
	routeName string
	createdAt time.Time
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
	return proto.WriteLinef(format, args...)
}

func debugEnabled() bool {
	v := strings.TrimSpace(os.Getenv("HOSTIT_DEBUG"))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("PLAYIT_DEBUG"))
	}
	if v == "" || v == "0" {
		return false
	}
	return true
}

func debugf(format string, args ...any) {
	if !debugEnabled() {
		return
	}
	log.Printf(format, args...)
}

func (st *serverState) routeTCPNoDelay(routeName string) bool {
	for _, rt := range st.cfg.Routes {
		if rt.Name != routeName {
			continue
		}
		if rt.TCPNoDelay == nil {
			return true
		}
		return *rt.TCPNoDelay
	}
	return true
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
			return err
		}
		backoff = 50 * time.Millisecond
		go st.handleControlConn(ctx, conn)
	}
}

func (st *serverState) handleControlConn(ctx context.Context, conn net.Conn) {
	setTCPKeepAlive(conn, 30*time.Second)
	// Control channel is latency-sensitive (NEW/CONN pairing, ROUTE updates).
	setTCPNoDelay(conn, true)
	setTCPQuickACK(conn, true)

	rw := lineproto.New(conn, conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := rw.ReadLine()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = rw.WriteLinef("ERR %s", "no hello")
		_ = conn.Close()
		return
	}
	cmd, rest := lineproto.Split2(line)
	if cmd != "HELLO" {
		_ = rw.WriteLinef("ERR %s", "expected HELLO")
		_ = conn.Close()
		return
	}
	expected := strings.TrimSpace(st.cfg.Token)
	if expected == "" {
		_ = rw.WriteLinef("ERR %s", "server token not set")
		_ = conn.Close()
		return
	}
	if !tokensEqualCT(expected, rest) {
		_ = rw.WriteLinef("ERR %s", "bad token (agent token must match server token)")
		_ = conn.Close()
		return
	}

	st.mu.Lock()
	if st.agentConn != nil {
		// Takeover: close the previous agent and accept the new one.
		_ = st.agentConn.Close()
		st.agentConn = nil
		st.agentProto = nil
		st.agentUDPAddr = nil
		st.agentUDPKeyID = 0
	}
	st.agentConn = conn
	st.agentProto = rw
	st.mu.Unlock()

	insec := strings.TrimSpace(st.cfg.DataAddrInsecure)
	if insec == "" {
		insec = "-"
	}
	_ = st.agentWriteLinef(conn, "OK %s %s", st.cfg.DataAddr, insec)
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
	_ = st.agentWriteLinef(conn, "UDPSEC %s %d %s %d %s", mode, st.cfg.UDPKeyID, curSalt, st.cfg.UDPPrevKeyID, prevSalt)
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
		_ = st.agentWriteLinef(conn, "ROUTE %s %s %s nodelay=%d tls=%d preconnect=%d", rt.Name, rt.Proto, rt.PublicAddr, nd, tlsFlag, pc)
	}
	_ = st.agentWriteLinef(conn, "READY")

	// Heartbeat: server pings agent periodically; agent replies with PONG.
	const pingEvery = 15 * time.Second
	const deadAfter = 60 * time.Second
	lastSeen := atomic.Int64{}
	lastSeen.Store(time.Now().UnixNano())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(deadAfter))
			line, err := rw.ReadLine()
			if err != nil {
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
					st.clearAgent(conn)
					_ = conn.Close()
					return
				}
				if err := st.agentWriteLinef(conn, "PING %s", newID()); err != nil {
					st.clearAgent(conn)
					_ = conn.Close()
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
	st.clearAgent(conn)
	_ = conn.Close()
}

func (st *serverState) clearAgent(conn net.Conn) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.agentConn == nil {
		return
	}
	if conn == nil || st.agentConn == conn {
		_ = st.agentConn.Close()
		st.agentConn = nil
		st.agentProto = nil
		st.agentUDPAddr = nil
		st.agentUDPKeyID = 0
	}
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
		_ = conn.Close()
		return
	}
	cmd, rest := lineproto.Split2(line)
	if cmd != "CONN" || rest == "" {
		_ = conn.Close()
		return
	}
	id := rest

	st.pendingMu.Lock()
	pend, ok := st.pending[id]
	if ok {
		delete(st.pending, id)
	}
	st.pendingMu.Unlock()
	if !ok {
		debugf("tunnel: CONN id=%s -> no pending match (closing)", id)
		_ = conn.Close()
		return
	}
	debugf("tunnel: CONN id=%s -> matched route=%s", id, pend.routeName)
	if tc := unwrapTCPConn(conn); tc != nil {
		_ = tc.SetReadBuffer(256 * 1024)
		_ = tc.SetWriteBuffer(256 * 1024)
	}
	if st.routeTCPNoDelay(pend.routeName) {
		setTCPNoDelay(conn, true)
		setTCPQuickACK(conn, true)
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
		st.dash.addEvent(routeName, DashboardEvent{TimeUnix: start.Unix(), Kind: "connect", RemoteIP: remoteIP, ConnID: id})
		defer st.dash.decActive(routeName)
	}

	if !st.hasAgent() {
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "reject_no_agent", RemoteIP: remoteIP, ConnID: id})
		}
		return
	}

	ch := make(chan net.Conn, 1)
	st.pendingMu.Lock()
	st.pending[id] = pendingConn{ch: ch, routeName: routeName, createdAt: start}
	st.pendingMu.Unlock()
	debugf("tunnel: NEW id=%s route=%s", id, routeName)

	st.newBatcher.add(id, routeName)
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
		st.pendingMu.Lock()
		delete(st.pending, id)
		st.pendingMu.Unlock()
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

func (st *serverState) getAgentUDPAddr() net.Addr {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.agentUDPAddr
}

func (st *serverState) getAgentUDPKeyID() uint32 {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.agentUDPKeyID
}

func (st *serverState) setAgentUDPAddr(addr net.Addr) {
	st.mu.Lock()
	st.agentUDPAddr = addr
	st.mu.Unlock()
}

func (st *serverState) setAgentUDPKeyID(id uint32) {
	st.mu.Lock()
	st.agentUDPKeyID = id
	st.mu.Unlock()
}

func (st *serverState) acceptAgentUDP(ctx context.Context) error {
	pc := st.udpData
	if pc == nil {
		return nil
	}

	// Determine worker count from environment or default to CPU count
	workers := 4
	if numWorkers := os.Getenv("HOSTIT_UDP_WORKERS"); numWorkers != "" {
		if n, err := strconv.Atoi(numWorkers); err == nil && n > 0 && n <= 64 {
			workers = n
		}
	}

	jobs := make(chan udpJob, workers*10)
	st.udpAgentJobs = jobs

	// Start worker pool
	for i := 0; i < workers; i++ {
		go st.udpAgentWorker(ctx, jobs)
	}

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
			close(jobs)
			return err
		}
		backoff = 50 * time.Millisecond

		// Copy packet data since buf is reused
		pktData := make([]byte, n)
		copy(pktData, buf[:n])
		udpBufPool.Put(bufPtr)

		select {
		case jobs <- udpJob{data: pktData, addr: addr}:
		default:
			// Drop packet if workers overwhelmed
		}
	}
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
			st.processAgentUDPPacket(job.data, job.addr)
		}
	}
}

func (st *serverState) processAgentUDPPacket(pkt []byte, addr net.Addr) {
	if len(pkt) == 0 {
		return
	}
	mode := strings.TrimSpace(st.cfg.UDPEncryptionMode)
	if st.cfg.DisableUDPEncryption {
		mode = "none"
	}
	switch pkt[0] {
	case udpproto.MsgReg:
		if !strings.EqualFold(mode, "none") {
			return
		}
		tok, ok := udpproto.DecodeReg(pkt)
		if !ok {
			return
		}
		expected := strings.TrimSpace(st.cfg.Token)
		if expected != "" && !tokensEqualCT(expected, tok) {
			return
		}
		if st.getAgentProto() == nil {
			return
		}
		st.setAgentUDPAddr(addr)
		st.setAgentUDPKeyID(0)
	case udpproto.MsgRegEnc2:
		if strings.EqualFold(mode, "none") {
			return
		}
		expected := strings.TrimSpace(st.cfg.Token)
		if expected == "" {
			return
		}
		kid, ok := udpproto.DecodeRegEnc2(st.udpKeys, expected, pkt)
		if !ok {
			return
		}
		if st.getAgentProto() == nil {
			return
		}
		st.setAgentUDPAddr(addr)
		st.setAgentUDPKeyID(kid)
	case udpproto.MsgData:
		if !strings.EqualFold(mode, "none") {
			return
		}
		route, client, payload, ok := udpproto.DecodeData(pkt)
		if !ok {
			return
		}
		agent := st.getAgentUDPAddr()
		if agent == nil || agent.String() != addr.String() {
			return
		}
		pc2 := st.publicUDP[route]
		if pc2 == nil {
			return
		}
		ua, err := net.ResolveUDPAddr("udp", client)
		if err != nil {
			return
		}
		_, _ = pc2.WriteTo(payload, ua)
	case udpproto.MsgDataEnc2:
		if strings.EqualFold(mode, "none") {
			return
		}
		route, client, payload, _, ok := udpproto.DecodeDataEnc2(st.udpKeys, pkt)
		if !ok {
			return
		}
		agent := st.getAgentUDPAddr()
		if agent == nil || agent.String() != addr.String() {
			return
		}
		pc2 := st.publicUDP[route]
		if pc2 == nil {
			return
		}
		ua, err := net.ResolveUDPAddr("udp", client)
		if err != nil {
			return
		}
		_, _ = pc2.WriteTo(payload, ua)
	}
}

func (st *serverState) acceptPublicUDP(ctx context.Context, pc net.PacketConn, routeName string) error {
	// Determine worker count
	workers := 4
	if numWorkers := os.Getenv("HOSTIT_UDP_WORKERS"); numWorkers != "" {
		if n, err := strconv.Atoi(numWorkers); err == nil && n > 0 && n <= 64 {
			workers = n
		}
	}

	jobs := make(chan udpJob, workers*10)
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
			close(jobs)
			return err
		}
		backoff = 50 * time.Millisecond

		// Copy packet data
		pktData := make([]byte, n)
		copy(pktData, buf[:n])
		udpBufPool.Put(bufPtr)

		select {
		case jobs <- udpJob{data: pktData, addr: clientAddr}:
		default:
			// Drop if workers overwhelmed
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
			st.processPublicUDPPacket(job.data, job.addr, routeName)
		}
	}
}

func (st *serverState) processPublicUDPPacket(pkt []byte, clientAddr net.Addr, routeName string) {
	agent := st.getAgentUDPAddr()
	if agent == nil {
		return
	}
	var msg []byte
	mode := strings.TrimSpace(st.cfg.UDPEncryptionMode)
	if st.cfg.DisableUDPEncryption {
		mode = "none"
	}
	if strings.EqualFold(mode, "none") || !st.udpKeys.Enabled() {
		msg = udpproto.EncodeData(routeName, clientAddr.String(), pkt)
	} else {
		kid := st.getAgentUDPKeyID()
		if kid == 0 {
			kid = st.cfg.UDPKeyID
		}
		msg = udpproto.EncodeDataEnc2ForKeyID(st.udpKeys, kid, routeName, clientAddr.String(), pkt)
	}
	_, _ = st.udpData.WriteTo(msg, agent)
}

func newID() string {
	idMu.Lock()
	v := idSource.Int63()
	idMu.Unlock()
	return fmt.Sprintf("%016x", v)
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
			close(pend.ch)
		}
	}
	for _, id := range toDelete {
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
