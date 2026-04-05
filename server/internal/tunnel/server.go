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
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/logging"
	"hostit/shared/protocol"
	"hostit/shared/relay"
)

type agentSession struct {
	conn        net.Conn
	cancel      context.CancelFunc
	remoteAddr  string
	connectTime time.Time
	writeMu     sync.Mutex
}

type Server struct {
	cfg ServerConfig

	derivedKeys map[string][]byte
	udpCiphers  map[string]cipher.AEAD

	mu          sync.RWMutex
	agentTCP    net.Conn
	agentEpoch  uint64
	agentUDP    netip.AddrPort
	agentUDPAt  time.Time
	udpDataConn *net.UDPConn
	controlLn   net.Listener
	dataLn      net.Listener

	publicTCP map[string]net.Listener
	publicUDP map[string]*net.UDPConn

	pendingTCP map[string]chan net.Conn

	clientIDCounter uint64

	pongCh chan []byte

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	dash *dashState

	routeCache atomic.Value

	sessionsMu sync.Mutex
	sessions   map[string]*agentSession
}

func makePendingTCPKey(routeName, clientID string) string {
	return routeName + ":" + clientID
}

func (s *Server) nextClientID() string {
	id := atomic.AddUint64(&s.clientIDCounter, 1)
	return strconv.FormatUint(id, 36)
}

type helloRoute struct {
	Name       string
	Proto      string
	PublicAddr string
	Encrypted  bool
	Algorithm  string
}

type ServerStatus struct {
	AgentConnected bool
}

func (s *Server) Status() ServerStatus {
	s.mu.RLock()
	connected := s.agentTCP != nil
	s.mu.RUnlock()

	return ServerStatus{AgentConnected: connected}
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
	s.mu.RUnlock()

	return s.dash.snapshot(now, connected)
}

type routeConfig struct {
	enabled     bool
	isEncrypted bool
}

func (s *Server) updateRouteCache() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	newCache := make(map[string]routeConfig)
	for _, rt := range s.cfg.Routes {
		newCache[rt.Name] = routeConfig{
			enabled:     rt.IsEnabled(),
			isEncrypted: rt.IsEncrypted(),
		}
	}
	s.routeCache.Store(newCache)
}

func (s *Server) SetRouteEnabled(name string, enabled bool) bool {
	s.mu.Lock()
	for i, rt := range s.cfg.Routes {
		if rt.Name == name {
			val := enabled
			s.cfg.Routes[i].Enabled = &val
			s.mu.Unlock()

			s.updateRouteCache()

			s.mu.Lock()
			if s.agentTCP != nil {
				routesMap := make(map[string]helloRoute)
				for _, r := range s.cfg.Routes {
					routesMap[r.Name] = helloRoute{
						Name:       r.Name,
						Proto:      r.Proto,
						PublicAddr: r.PublicAddr,
						Encrypted:  r.IsEncrypted(),
						Algorithm:  s.cfg.EncryptionAlgorithm,
					}
				}
				routesJSON, _ := json.Marshal(routesMap)
				helloPkt := &protocol.Packet{
					Type:    protocol.TypeHello,
					Payload: routesJSON,
				}
				remoteAddr := s.agentTCP.RemoteAddr().String()
				s.mu.Unlock()
				s.sessionsMu.Lock()
				if session, ok := s.sessions[remoteAddr]; ok {
					session.writeMu.Lock()
					s.agentTCP.SetWriteDeadline(time.Now().Add(5 * time.Second))
					protocol.WritePacket(s.agentTCP, helloPkt)
					session.writeMu.Unlock()
				}
				s.sessionsMu.Unlock()
			} else {
				s.mu.Unlock()
			}
			return true
		}
	}
	s.mu.Unlock()
	return false
}

func (s *Server) GetRouteEnabled(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rt := range s.cfg.Routes {
		if rt.Name == name {
			return rt.IsEnabled()
		}
	}
	return false
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
			agent.SetWriteDeadline(time.Now().Add(2 * time.Second))
			err := protocol.WritePacket(agent, pkt)
			session.writeMu.Unlock()
			s.sessionsMu.Unlock()

			if err != nil {
				continue
			}
		} else {
			s.sessionsMu.Unlock()
			continue
		}

		timeout := time.After(2 * time.Second)
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
			agent.SetWriteDeadline(time.Now().Add(5 * time.Second))
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
				if err := protocol.WritePacket(agent, pkt); err != nil {
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

	timeout := time.After(5 * time.Second)
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

func (s *Server) Run(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	s.Stop()
	return nil
}

func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		cfg:         cfg,
		derivedKeys: make(map[string][]byte),
		udpCiphers:  make(map[string]cipher.AEAD),
		publicTCP:   make(map[string]net.Listener),
		publicUDP:   make(map[string]*net.UDPConn),
		pendingTCP:  make(map[string]chan net.Conn),
		dash:        newDashState(),
		sessions:    make(map[string]*agentSession),
	}
	for _, rt := range cfg.Routes {
		if rt.IsEncrypted() {
			key, err := crypto.DeriveKey(cfg.Token, cfg.EncryptionAlgorithm)
			if err != nil {
				logging.Global().RouteError(rt.Name, logging.CatTCP, "failed to derive key", map[string]string{"error": err.Error()})
			} else if len(key) == 0 {
				logging.Global().RouteError(rt.Name, logging.CatTCP, "encryption_algorithm not set for encrypted route", nil)
			} else {
				s.derivedKeys[rt.Name] = key
				cipher, err := crypto.NewUDPCipher(key)
				if err != nil {
					logging.Global().RouteError(rt.Name, logging.CatTCP, "failed to create UDP cipher", map[string]string{"error": err.Error()})
				} else {
					s.udpCiphers[rt.Name] = cipher
				}
			}
		}
	}
	s.updateRouteCache()
	s.setupLoggingHook()
	return s
}

func (s *Server) setupLoggingHook() {
	logging.Global().AddHook(func(entry logging.LogEntry) {
		if entry.Route == "" {
			return
		}
		ev := DashboardEvent{
			TimeUnix: entry.Timestamp / 1000,
			Kind:     entry.Level + "_" + entry.Category,
			Detail:   entry.Message,
			Route:    entry.Route,
		}
		if entry.Fields != nil {
			if ip, ok := entry.Fields["remote"]; ok {
				ev.RemoteIP = ip
			}
			if ip, ok := entry.Fields["ip"]; ok {
				ev.RemoteIP = ip
			}
			if detail, ok := entry.Fields["detail"]; ok {
				if ev.Detail != "" {
					ev.Detail += " " + detail
				} else {
					ev.Detail = detail
				}
			}
		}
		s.dash.addEvent(entry.Route, ev)
	})
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
			return fmt.Errorf("data listen failed: %w", err)
		}
	} else {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS cert: %w", err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		controlLn, err = tls.Listen("tcp", s.cfg.ControlAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("control tls listen failed: %w", err)
		}
		dataLn, err = tls.Listen("tcp", s.cfg.DataAddr, tlsConfig)
		if err != nil {
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

	for _, rt := range s.cfg.Routes {
		if rt.Proto == "tcp" || rt.Proto == "both" {
			ln, err := net.Listen("tcp", rt.PublicAddr)
			if err != nil {
				logging.Global().RouteError(rt.Name, logging.CatTCP, "failed to listen on public tcp", map[string]string{"addr": rt.PublicAddr, "error": err.Error()})
				continue
			}
			s.publicTCP[rt.Name] = ln
			s.wg.Add(1)
			go s.acceptPublicTCP(ln, rt.Name)
		}
		if rt.Proto == "udp" || rt.Proto == "both" {
			addr, err := net.ResolveUDPAddr("udp", rt.PublicAddr)
			if err != nil {
				logging.Global().RouteError(rt.Name, logging.CatUDP, "failed to resolve public udp", map[string]string{"addr": rt.PublicAddr, "error": err.Error()})
				continue
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				logging.Global().RouteError(rt.Name, logging.CatUDP, "failed to listen on public udp", map[string]string{"addr": rt.PublicAddr, "error": err.Error()})
				continue
			}
			conn.SetReadBuffer(8 * 1024 * 1024)
			conn.SetWriteBuffer(8 * 1024 * 1024)
			s.publicUDP[rt.Name] = conn
			s.wg.Add(1)
			go s.acceptPublicUDP(conn, rt.Name)
		}
	}

	logging.Global().RouteInfo("", logging.CatSystem, "Server started", map[string]string{"control": s.cfg.ControlAddr, "data": s.cfg.DataAddr})
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
			logging.Global().RouteError("", logging.CatTCP, "control accept error", map[string]string{"error": err.Error()})
			continue
		}

		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := crypto.AuthenticateServer(conn, s.cfg.Token); err != nil {
			logging.Global().RouteError("", logging.CatTCP, "control auth failed", map[string]string{"remote": conn.RemoteAddr().String(), "error": err.Error()})
			conn.Close()
			continue
		}
		conn.SetDeadline(time.Time{})

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}

		remoteAddr := conn.RemoteAddr().String()

		s.sessionsMu.Lock()
		if oldSession, exists := s.sessions[remoteAddr]; exists {
			logging.Global().RouteInfo("", logging.CatTCP, "Terminating previous session", map[string]string{"remote": remoteAddr})
			if oldSession.cancel != nil {
				oldSession.cancel()
			}
			if oldSession.conn != nil {
				oldSession.conn.Close()
			}
			delete(s.sessions, remoteAddr)
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

		s.mu.Lock()
		currentEpoch := s.agentEpoch + 1
		s.agentEpoch = currentEpoch
		s.agentTCP = conn
		s.agentUDP = netip.AddrPort{}
		s.agentUDPAt = time.Time{}
		for clientID, ch := range s.pendingTCP {
			close(ch)
			delete(s.pendingTCP, clientID)
		}
		s.mu.Unlock()

		logging.Global().RouteInfo("", logging.CatTCP, "Agent connected to control", map[string]string{"remote": remoteAddr})

		routesMap := make(map[string]helloRoute)
		for _, rt := range s.cfg.Routes {
			routesMap[rt.Name] = helloRoute{
				Name:       rt.Name,
				Proto:      rt.Proto,
				PublicAddr: rt.PublicAddr,
				Encrypted:  rt.IsEncrypted(),
				Algorithm:  s.cfg.EncryptionAlgorithm,
			}
		}
		routesJSON, _ := json.Marshal(routesMap)
		helloPkt := &protocol.Packet{
			Type:    protocol.TypeHello,
			Payload: routesJSON,
		}
		session.writeMu.Lock()
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := protocol.WritePacket(conn, helloPkt); err != nil {
			logging.Global().RouteError("", logging.CatTCP, "failed to send HELLO", map[string]string{"error": err.Error()})
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
				ticker := time.NewTicker(15 * time.Second)
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
							c.SetWriteDeadline(time.Now().Add(5 * time.Second))
							protocol.WritePacket(c, &protocol.Packet{Type: protocol.TypePing})
							session.writeMu.Unlock()
						}
					}
				}
			}()

			go func() {
				ticker := time.NewTicker(30 * time.Second)
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
							if time.Since(lastPongTime) >= 60*time.Second {
								logging.Global().RouteError("", logging.CatTCP, "agent health check timeout, closing connection", nil)
								c.Close()
								return
							}
						}
					}
				}
			}()

			for {
				select {
				case <-sessionCtx.Done():
					return
				default:
				}

				c.SetReadDeadline(time.Now().Add(45 * time.Second))
				pkt, err := protocol.ReadPacket(c)
				if err != nil {
					break
				}
				if pkt.Type == protocol.TypePing {
					session.writeMu.Lock()
					c.SetWriteDeadline(time.Now().Add(5 * time.Second))
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
			}

			s.mu.Lock()
			if s.agentTCP == c && s.agentEpoch == epoch {
				s.agentTCP = nil
				for clientID, ch := range s.pendingTCP {
					close(ch)
					delete(s.pendingTCP, clientID)
				}
				logging.Global().RouteInfo("", logging.CatTCP, "Agent disconnected from control", nil)
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
			logging.Global().RouteError("", logging.CatTCP, "data accept error", map[string]string{"error": err.Error()})
			continue
		}

		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := crypto.AuthenticateServer(conn, s.cfg.Token); err != nil {
			logging.Global().RouteError("", logging.CatTCP, "data auth failed", map[string]string{"remote": conn.RemoteAddr().String(), "error": err.Error()})
			conn.Close()
			continue
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

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
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		routeName := string(routeBytes)

		s.mu.RLock()
		var isEncrypted bool
		routeFound := false
		for _, rt := range s.cfg.Routes {
			if rt.Name == routeName {
				isEncrypted = rt.IsEncrypted()
				routeFound = true
				break
			}
		}
		s.mu.RUnlock()

		if !routeFound {
			logging.Global().RouteError("", logging.CatTCP, "unknown route from agent data connection", map[string]string{"route": routeName})
			conn.Close()
			continue
		}

		if isEncrypted {
			key := s.derivedKeys[routeName]
			if key == nil {
				logging.Global().RouteError(routeName, logging.CatTCP, "failed to derive key: key is nil", nil)
				conn.Close()
				continue
			}
			wrappedConn, err := crypto.WrapTCP(conn, key)
			if err != nil {
				logging.Global().RouteError(routeName, logging.CatTCP, "failed to wrap tcp", map[string]string{"error": err.Error()})
				conn.Close()
				continue
			}
			conn = wrappedConn
		}

		s.mu.Lock()
		ch, ok := s.pendingTCP[makePendingTCPKey(routeName, clientID)]
		if ok {
			delete(s.pendingTCP, makePendingTCPKey(routeName, clientID))
			conn.SetReadDeadline(time.Time{})
		}
		s.mu.Unlock()

		if ok {
			ch <- conn
		} else {
			logging.Global().RouteWarn(routeName, logging.CatTCP, "no pending connection, closing agent data connection", map[string]string{"route": routeName, "client": clientID})
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
			logging.Global().RouteError(routeName, logging.CatTCP, "public tcp accept error", map[string]string{"error": err.Error()})
			continue
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetKeepAlive(true)
			tcpConn.SetKeepAlivePeriod(5 * time.Second)
		}
		clientID := s.nextClientID()
		logging.Global().RouteInfo(routeName, logging.CatTCP, "New public TCP connection", map[string]string{"route": routeName, "client": clientID})

		s.mu.RLock()
		agent := s.agentTCP
		enabled := false
		routeFound := false
		for _, rt := range s.cfg.Routes {
			if rt.Name == routeName {
				enabled = rt.IsEnabled()
				routeFound = true
				break
			}
		}
		s.mu.RUnlock()

		if !routeFound {
			logging.Global().RouteWarn(routeName, logging.CatTCP, "public tcp connection for unknown route, closing", map[string]string{"route": routeName})
			conn.Close()
			continue
		}

		if !enabled {
			logging.Global().RouteWarn(routeName, logging.CatTCP, "route is disabled, closing public tcp connection", map[string]string{"route": routeName})
			conn.Close()
			continue
		}

		if agent == nil {
			logging.Global().RouteWarn(routeName, logging.CatTCP, "no agent connected, closing public tcp connection", map[string]string{"route": routeName})
			conn.Close()
			continue
		}

		remoteAddr := agent.RemoteAddr().String()

		ch := make(chan net.Conn, 1)
		s.mu.Lock()
		s.pendingTCP[makePendingTCPKey(routeName, clientID)] = ch
		s.mu.Unlock()

		reqPkt := &protocol.Packet{
			Type:   protocol.TypeConnect,
			Route:  routeName,
			Client: clientID,
		}
		s.sessionsMu.Lock()
		if session, ok := s.sessions[remoteAddr]; ok {
			session.writeMu.Lock()
			agent.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := protocol.WritePacket(agent, reqPkt); err != nil {
				session.writeMu.Unlock()
				s.sessionsMu.Unlock()
				conn.Close()
				s.mu.Lock()
				delete(s.pendingTCP, makePendingTCPKey(routeName, clientID))
				s.mu.Unlock()
				continue
			}
			session.writeMu.Unlock()
		} else {
			s.sessionsMu.Unlock()
			conn.Close()
			s.mu.Lock()
			delete(s.pendingTCP, makePendingTCPKey(routeName, clientID))
			s.mu.Unlock()
			continue
		}
		s.sessionsMu.Unlock()

		go func(c net.Conn, clientID string) {
			defer c.Close()
			select {
			case agentConn := <-ch:
				if agentConn == nil {
					return
				}
				s.dash.addConn(time.Now())
				s.dash.incActive(routeName)
				logging.Global().RouteInfo(routeName, logging.CatTCP, "Connection established", map[string]string{"client": clientID})
				defer s.dash.decActive(routeName)
				defer logging.Global().RouteInfo(routeName, logging.CatTCP, "Connection closed", map[string]string{"client": clientID})

				countBytes := func(n int) {
					s.dash.addBytes(time.Now(), int64(n))
				}
				relay.Proxy(&countingConn{Conn: c, onRead: countBytes}, &countingConn{Conn: agentConn, onRead: countBytes})

			case <-time.After(s.cfg.PairTimeout):
				logging.Global().RouteWarn(routeName, logging.CatTCP, "timeout waiting for agent data connection", map[string]string{"route": routeName, "client": clientID})
				s.mu.Lock()
				delete(s.pendingTCP, makePendingTCPKey(routeName, clientID))
				s.mu.Unlock()
				select {
				case lateConn := <-ch:
					if lateConn != nil {
						lateConn.Close()
					}
				default:
				}
			}
		}(conn, clientID)
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

	addrCache := sync.Map{}
	addrCacheSize := 0

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

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

		s.mu.Lock()
		if pkt.Type == protocol.TypeRegister {
			if !s.agentUDP.IsValid() || s.agentUDP != addr {
				s.agentUDP = addr
				logging.Global().RouteInfo("", logging.CatUDP, "Agent UDP address registered", map[string]string{"addr": addr.String()})
			}
			s.agentUDPAt = time.Now()
		} else if !s.agentUDP.IsValid() || s.agentUDP != addr {
			s.agentUDP = addr
			s.agentUDPAt = time.Now()
		}
		s.mu.Unlock()

		if pkt.Type == protocol.TypeRegister {
			continue
		}

		if pkt.Type == protocol.TypeData {
			s.mu.RLock()
			pubConn, ok := s.publicUDP[pkt.Route]
			udpCipher := s.udpCiphers[pkt.Route]
			s.mu.RUnlock()

			if !ok {
				continue
			}

			cache := s.routeCache.Load().(map[string]routeConfig)
			rc, ok := cache[pkt.Route]
			if !ok {
				logging.Global().RouteDebug(pkt.Route, logging.CatUDP, "no route config in acceptAgentUDP", nil)
				continue
			}

			payload := pkt.Payload
			if rc.isEncrypted {
				if udpCipher == nil {
					logging.Global().RouteDebug(pkt.Route, logging.CatUDP, "missing UDP cipher for encrypted route", nil)
					continue
				}
				decrypted, err := crypto.DecryptUDP(udpCipher, decryptBuf, payload)
				if err != nil {
					logging.Global().RouteDebug(pkt.Route, logging.CatUDP, "UDP decryption failed", map[string]string{"error": err.Error()})
					continue
				}
				payload = decrypted
			}

			clientKey := string([]byte(pkt.Client))
			clientAddrVal, ok := addrCache.Load(clientKey)
			if !ok {
				clientAddr, err := net.ResolveUDPAddr("udp", clientKey)
				if err != nil {
					continue
				}
				clientAddrVal = clientAddr
				addrCache.Store(clientKey, clientAddrVal)
				addrCacheSize++
				if addrCacheSize > 10000 {
					addrCache = sync.Map{}
					addrCacheSize = 0
				}
			}
			clientAddr, ok := clientAddrVal.(*net.UDPAddr)
			if !ok || clientAddr == nil {
				continue
			}

			s.dash.addBytes(time.Now(), int64(len(payload)))
			pubConn.WriteToUDP(payload, clientAddr)
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

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

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

		s.mu.RLock()
		agentAddr := s.agentUDP
		agentUDPAt := s.agentUDPAt
		udpCipher := s.udpCiphers[routeName]
		s.mu.RUnlock()

		if !agentAddr.IsValid() {
			continue
		}

		if !agentUDPAt.IsZero() && time.Since(agentUDPAt) > 60*time.Second {
			s.mu.Lock()
			if !s.agentUDPAt.IsZero() && time.Since(s.agentUDPAt) > 60*time.Second {
				logging.Global().RouteInfo("", logging.CatUDP, "Agent UDP address timed out after 60s inactivity", nil)
				s.agentUDP = netip.AddrPort{}
			}
			s.mu.Unlock()
			continue
		}

		cache := s.routeCache.Load().(map[string]routeConfig)
		rc, ok := cache[routeName]
		if !ok {
			logging.Global().RouteDebug(routeName, logging.CatUDP, "no route config in acceptPublicUDP", nil)
			continue
		}
		if !rc.enabled {
			logging.Global().RouteDebug(routeName, logging.CatUDP, "route is disabled", nil)
			continue
		}

		payload := buf[:n]
		if rc.isEncrypted {
			if udpCipher == nil {
				logging.Global().RouteDebug(routeName, logging.CatUDP, "missing UDP cipher for encrypted route", nil)
				continue
			}
			encrypted, err := crypto.EncryptUDP(udpCipher, encryptBuf, payload)
			if err != nil {
				logging.Global().RouteDebug(routeName, logging.CatUDP, "UDP encryption failed", map[string]string{"error": err.Error()})
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

		s.dash.addBytes(time.Now(), int64(len(pkt.Payload)))
		s.udpDataConn.WriteToUDPAddrPort(data, agentAddr)
	}
}
