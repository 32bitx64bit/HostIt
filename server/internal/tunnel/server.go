package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"playit-prototype/server/internal/lineproto"
	"playit-prototype/server/internal/udpproto"
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
	if cfg.PairTimeout == 0 {
		cfg.PairTimeout = 10 * time.Second
	}
	return &Server{cfg: cfg, st: &serverState{cfg: cfg, pending: map[string]chan net.Conn{}, publicUDP: map[string]net.PacketConn{}}}
}

func (s *Server) Status() ServerStatus {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	return ServerStatus{AgentConnected: s.st.agentConn != nil}
}

func Serve(ctx context.Context, cfg ServerConfig) error {
	return NewServer(cfg).Run(ctx)
}

func (s *Server) Run(ctx context.Context) error {
	controlLn, err := net.Listen("tcp", s.cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("listen control: %w", err)
	}
	defer controlLn.Close()

	dataLn, err := net.Listen("tcp", s.cfg.DataAddr)
	if err != nil {
		return fmt.Errorf("listen data: %w", err)
	}
	defer dataLn.Close()

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
		_ = udpDataConn.Close()
		for _, x := range publicTCP {
			_ = x.ln.Close()
		}
		for _, x := range publicUDP {
			_ = x.pc.Close()
		}
		st.clearAgent(nil)
	}()

	errCh := make(chan error, 3+len(publicTCP)+len(publicUDP))
	go func() { errCh <- st.acceptControl(ctx, controlLn) }()
	go func() { errCh <- st.acceptData(ctx, dataLn) }()
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

type serverState struct {
	cfg ServerConfig

	mu         sync.Mutex
	agentConn  net.Conn
	agentProto *lineproto.RW
	agentUDPAddr net.Addr
	udpData net.PacketConn
	publicUDP map[string]net.PacketConn

	pendingMu sync.Mutex
	pending   map[string]chan net.Conn
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
	if expected != "" && rest != expected {
		_ = rw.WriteLinef("ERR %s", "bad token (agent token must match server token)")
		_ = conn.Close()
		return
	}

	st.mu.Lock()
	if st.agentConn != nil {
		_ = rw.WriteLinef("ERR %s", "agent already connected")
		st.mu.Unlock()
		_ = conn.Close()
		return
	}
	st.agentConn = conn
	st.agentProto = rw
	st.mu.Unlock()

	_ = rw.WriteLinef("OK %s", st.cfg.DataAddr)

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
	ch, ok := st.pending[id]
	if ok {
		delete(st.pending, id)
	}
	st.pendingMu.Unlock()
	if !ok {
		_ = conn.Close()
		return
	}

	select {
	case ch <- conn:
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
		go st.handlePublicConn(ctx, clientConn, routeName)
	}
}

func (st *serverState) handlePublicConn(ctx context.Context, clientConn net.Conn, routeName string) {
	defer clientConn.Close()

	proto := st.getAgentProto()
	if proto == nil {
		return
	}

	id := newID()
	ch := make(chan net.Conn, 1)
	st.pendingMu.Lock()
	st.pending[id] = ch
	st.pendingMu.Unlock()

	err := proto.WriteLinef("NEW %s %s", id, routeName)
	if err != nil {
		st.pendingMu.Lock()
		delete(st.pending, id)
		st.pendingMu.Unlock()
		return
	}

	select {
	case <-ctx.Done():
		return
	case agentConn := <-ch:
		if agentConn == nil {
			return
		}
		bidirPipe(clientConn, agentConn)
	case <-time.After(st.cfg.PairTimeout):
		st.pendingMu.Lock()
		delete(st.pending, id)
		st.pendingMu.Unlock()
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

func (st *serverState) setAgentUDPAddr(addr net.Addr) {
	st.mu.Lock()
	st.agentUDPAddr = addr
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
		msg := udpproto.EncodeData(routeName, clientAddr.String(), buf[:n])
		_, _ = st.udpData.WriteTo(msg, agent)
	}
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func setTCPKeepAlive(conn net.Conn, period time.Duration) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(period)
}
