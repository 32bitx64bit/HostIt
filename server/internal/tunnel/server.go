package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hostit/server/internal/lineproto"
	"hostit/server/internal/udpproto"
)

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
	st := &serverState{cfg: cfg, pending: map[string]pendingConn{}, publicUDP: map[string]net.PacketConn{}, dash: newDashState()}
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
	for _, x := range publicTCP {
		go func(name string, l net.Listener) { errCh <- st.acceptPublicTCP(ctx, l, name) }(x.name, x.ln)
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
	agentUDPAddr  net.Addr
	agentUDPKeyID uint32
	udpData       net.PacketConn
	publicUDP     map[string]net.PacketConn

	pendingMu sync.Mutex
	pending   map[string]pendingConn
}

type pendingConn struct {
	ch        chan net.Conn
	routeName string
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
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go st.handleControlConn(ctx, conn)
	}
}

func (st *serverState) handleControlConn(ctx context.Context, conn net.Conn) {
	setTCPKeepAlive(conn, 30*time.Second)

	rw := lineproto.New(conn, conn)
	line, err := rw.ReadLine()
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
	provided := strings.TrimSpace(rest)
	if provided != expected {
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
	_ = rw.WriteLinef("OK %s %s", st.cfg.DataAddr, insec)
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
	_ = rw.WriteLinef("UDPSEC %s %d %s %d %s", mode, st.cfg.UDPKeyID, curSalt, st.cfg.UDPPrevKeyID, prevSalt)
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
		_ = rw.WriteLinef("ROUTE %s %s %s nodelay=%d tls=%d preconnect=%d", rt.Name, rt.Proto, rt.PublicAddr, nd, tlsFlag, pc)
	}
	_ = rw.WriteLinef("READY")

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
				_ = rw.WriteLinef("PONG %s", rest)
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
				if err := rw.WriteLinef("PING %s", newID()); err != nil {
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
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		setTCPKeepAlive(conn, 30*time.Second)
		go st.handleDataConn(conn)
	}
}

func (st *serverState) handleDataConn(conn net.Conn) {
	rw := lineproto.New(conn, conn)
	line, err := rw.ReadLine()
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
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			return err
		}
		setTCPKeepAlive(clientConn, 30*time.Second)
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

	proto := st.getAgentProto()
	if proto == nil {
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "reject_no_agent", RemoteIP: remoteIP, ConnID: id})
		}
		return
	}

	ch := make(chan net.Conn, 1)
	st.pendingMu.Lock()
	st.pending[id] = pendingConn{ch: ch, routeName: routeName}
	st.pendingMu.Unlock()
	debugf("tunnel: NEW id=%s route=%s", id, routeName)

	err := proto.WriteLinef("NEW %s %s", id, routeName)
	if err != nil {
		st.pendingMu.Lock()
		delete(st.pending, id)
		st.pendingMu.Unlock()
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "control_write_failed", RemoteIP: remoteIP, ConnID: id, Detail: err.Error()})
		}
		return
	}

	select {
	case <-ctx.Done():
		return
	case agentConn := <-ch:
		if agentConn == nil {
			return
		}
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "paired", RemoteIP: remoteIP, ConnID: id})
		}
		a2b, b2a := bidirPipeCount(clientConn, agentConn)
		if st.dash != nil {
			bytes := a2b + b2a
			st.dash.addBytes(time.Now(), bytes)
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "disconnect", RemoteIP: remoteIP, ConnID: id, Bytes: bytes, DurationMS: time.Since(start).Milliseconds()})
		}
	case <-time.After(st.cfg.PairTimeout):
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
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		pkt := buf[:n]
		if len(pkt) == 0 {
			continue
		}
		switch pkt[0] {
		case udpproto.MsgReg:
			tok, ok := udpproto.DecodeReg(pkt)
			if !ok {
				continue
			}
			expected := strings.TrimSpace(st.cfg.Token)
			if expected != "" && tok != expected {
				continue
			}
			if st.getAgentProto() == nil {
				continue
			}
			st.setAgentUDPAddr(addr)
			st.setAgentUDPKeyID(0)
		case udpproto.MsgRegEnc2:
			expected := strings.TrimSpace(st.cfg.Token)
			if expected == "" {
				continue
			}
			kid, ok := udpproto.DecodeRegEnc2(st.udpKeys, expected, pkt)
			if !ok {
				continue
			}
			if st.getAgentProto() == nil {
				continue
			}
			st.setAgentUDPAddr(addr)
			st.setAgentUDPKeyID(kid)
		case udpproto.MsgData:
			route, client, payload, ok := udpproto.DecodeData(pkt)
			if !ok {
				continue
			}
			agent := st.getAgentUDPAddr()
			if agent == nil || agent.String() != addr.String() {
				continue
			}
			pc2 := st.publicUDP[route]
			if pc2 == nil {
				continue
			}
			ua, err := net.ResolveUDPAddr("udp", client)
			if err != nil {
				continue
			}
			_, _ = pc2.WriteTo(payload, ua)
		case udpproto.MsgDataEnc2:
			route, client, payload, _, ok := udpproto.DecodeDataEnc2(st.udpKeys, pkt)
			if !ok {
				continue
			}
			agent := st.getAgentUDPAddr()
			if agent == nil || agent.String() != addr.String() {
				continue
			}
			pc2 := st.publicUDP[route]
			if pc2 == nil {
				continue
			}
			ua, err := net.ResolveUDPAddr("udp", client)
			if err != nil {
				continue
			}
			_, _ = pc2.WriteTo(payload, ua)
		default:
			continue
		}
	}
}

func (st *serverState) acceptPublicUDP(ctx context.Context, pc net.PacketConn, routeName string) error {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		agent := st.getAgentUDPAddr()
		if agent == nil {
			continue
		}
		var msg []byte
		mode := strings.TrimSpace(st.cfg.UDPEncryptionMode)
		if st.cfg.DisableUDPEncryption {
			mode = "none"
		}
		if strings.EqualFold(mode, "none") || !st.udpKeys.Enabled() {
			msg = udpproto.EncodeData(routeName, clientAddr.String(), buf[:n])
		} else {
			kid := st.getAgentUDPKeyID()
			if kid == 0 {
				kid = st.cfg.UDPKeyID
			}
			msg = udpproto.EncodeDataEnc2ForKeyID(st.udpKeys, kid, routeName, clientAddr.String(), buf[:n])
		}
		_, _ = st.udpData.WriteTo(msg, agent)
	}
}

func newID() string {
	var b [8]byte
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
