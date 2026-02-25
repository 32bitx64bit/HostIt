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
	"sync"
	"sync/atomic"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/logging"
	"hostit/shared/protocol"
)

type Server struct {
	cfg ServerConfig

	derivedKey []byte
	udpCipher  cipher.AEAD

	mu          sync.RWMutex
	agentTCP    net.Conn
	agentUDP    netip.AddrPort
	udpDataConn *net.UDPConn
	controlLn   net.Listener
	dataLn      net.Listener

	publicTCP map[string]net.Listener
	publicUDP map[string]*net.UDPConn

	pendingTCP map[string]chan net.Conn

	pongCh chan []byte

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	dash *dashState
	
	// We use an atomic.Value to store the route cache so it can be updated safely
	// and read without locks in the hot path.
	routeCache atomic.Value
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
				s.agentTCP.SetWriteDeadline(time.Now().Add(5 * time.Second))
				protocol.WritePacket(s.agentTCP, helloPkt)
				s.agentTCP.SetWriteDeadline(time.Time{})
			}
			s.mu.Unlock()
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

	// Phase 1: Latency test
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
		agent.SetWriteDeadline(time.Now().Add(2 * time.Second))
		err := protocol.WritePacket(agent, pkt)
		agent.SetWriteDeadline(time.Time{})
		if err != nil {
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

	// Phase 2: Bandwidth test
	bwCount := 100
	bwPayloadBytes := 64000 // 64KB
	var bwSent int32
	var bwRecv int
	var bytesSent int64
	var bytesRecv int64

	bwStart := time.Now()
	sendDone := make(chan struct{})

	go func() {
		defer close(sendDone)
		agent.SetWriteDeadline(time.Now().Add(5 * time.Second))
		for i := 0; i < bwCount; i++ {
			if ctx.Err() != nil {
				break
			}
			payload := make([]byte, bwPayloadBytes)
			binary.BigEndian.PutUint64(payload, uint64(1000+i)) // offset seq to avoid collision
			pkt := &protocol.Packet{Type: protocol.TypePing, Payload: payload}

			if err := protocol.WritePacket(agent, pkt); err != nil {
				break
			}
			bwSent++
			bytesSent += int64(bwPayloadBytes)
		}
		agent.SetWriteDeadline(time.Time{})
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
	key, _ := crypto.DeriveKey(cfg.Token, cfg.EncryptionAlgorithm)
	udpCipher, _ := crypto.NewUDPCipher(key)
	s := &Server{
		cfg:        cfg,
		derivedKey: key,
		udpCipher:  udpCipher,
		publicTCP:  make(map[string]net.Listener),
		publicUDP:  make(map[string]*net.UDPConn),
		pendingTCP: make(map[string]chan net.Conn),
		dash:       newDashState(),
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
				logging.Global().Errorf(logging.CatTCP, "failed to listen on public tcp %s: %v", rt.PublicAddr, err)
				continue
			}
			s.publicTCP[rt.Name] = ln
			s.wg.Add(1)
			go s.acceptPublicTCP(ln, rt.Name)
		}
		if rt.Proto == "udp" || rt.Proto == "both" {
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

		// Mutual auth
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := crypto.AuthenticateServer(conn, s.cfg.Token); err != nil {
			logging.Global().Errorf(logging.CatTCP, "control auth failed: %v", err)
			conn.Close()
			continue
		}
		conn.SetDeadline(time.Time{})

		s.mu.Lock()
		if s.agentTCP != nil {
			s.agentTCP.Close()
		}
		s.agentTCP = conn
		s.agentUDP = netip.AddrPort{}
		// Clear stale pending TCP connections
		for clientID, ch := range s.pendingTCP {
			close(ch)
			delete(s.pendingTCP, clientID)
		}
		s.mu.Unlock()

		logging.Global().Infof(logging.CatTCP, "Agent connected to control")

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
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := protocol.WritePacket(conn, helloPkt); err != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to send HELLO: %v", err)
			conn.Close()
			s.mu.Lock()
			if s.agentTCP == conn {
				s.agentTCP = nil
			}
			s.mu.Unlock()
			continue
		}
		conn.SetWriteDeadline(time.Time{})

		// Keep connection open and detect disconnect
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()

			pingCtx, pingCancel := context.WithCancel(s.ctx)
			defer pingCancel()
			go func() {
				ticker := time.NewTicker(15 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-pingCtx.Done():
						return
					case <-ticker.C:
						s.mu.RLock()
						isAgent := s.agentTCP == c
						s.mu.RUnlock()
						if isAgent {
							c.SetWriteDeadline(time.Now().Add(5 * time.Second))
							protocol.WritePacket(c, &protocol.Packet{Type: protocol.TypePing})
							c.SetWriteDeadline(time.Time{})
						}
					}
				}
			}()

			for {
				c.SetReadDeadline(time.Now().Add(45 * time.Second))
				pkt, err := protocol.ReadPacket(c)
				if err != nil {
					break
				}
				if pkt.Type == protocol.TypePing {
					c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					protocol.WritePacket(c, &protocol.Packet{
						Type:    protocol.TypePong,
						Payload: pkt.Payload,
					})
					c.SetWriteDeadline(time.Time{})
					continue
				}
				if pkt.Type == protocol.TypePong {
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
			if s.agentTCP == c {
				s.agentTCP = nil
				s.agentUDP = netip.AddrPort{}
				// Clear pending TCP connections
				for clientID, ch := range s.pendingTCP {
					close(ch)
					delete(s.pendingTCP, clientID)
				}
				logging.Global().Infof(logging.CatTCP, "Agent disconnected from control")
			}
			s.mu.Unlock()
		}(conn)
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

		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := crypto.AuthenticateServer(conn, s.cfg.Token); err != nil {
			logging.Global().Errorf(logging.CatTCP, "data auth failed: %v", err)
			conn.Close()
			continue
		}
		conn.SetDeadline(time.Time{})

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
		_ = string(routeBytes) // routeName not needed here

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
		conn.SetReadDeadline(time.Time{})

		routeName := string(routeBytes)

		s.mu.RLock()
		var isEncrypted bool
		for _, rt := range s.cfg.Routes {
			if rt.Name == routeName {
				isEncrypted = rt.IsEncrypted()
				break
			}
		}
		s.mu.RUnlock()

		if isEncrypted {
			if s.derivedKey == nil {
				logging.Global().Errorf(logging.CatTCP, "failed to derive key for route %s: key is nil", routeName)
				conn.Close()
				continue
			}
			conn, err = crypto.WrapTCP(conn, s.derivedKey)
			if err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to wrap tcp for route %s: %v", routeName, err)
				conn.Close()
				continue
			}
		}

		s.mu.Lock()
		ch, ok := s.pendingTCP[clientID]
		if ok {
			delete(s.pendingTCP, clientID)
		}
		s.mu.Unlock()

		if ok {
			ch <- conn
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

		clientID := fmt.Sprintf("%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano())
		logging.Global().Infof(logging.CatTCP, "New public TCP connection route=%s client=%s", routeName, clientID)

		s.mu.RLock()
		agent := s.agentTCP
		enabled := false
		for _, rt := range s.cfg.Routes {
			if rt.Name == routeName {
				enabled = rt.IsEnabled()
				break
			}
		}
		s.mu.RUnlock()

		if agent == nil || !enabled {
			conn.Close()
			continue
		}

		ch := make(chan net.Conn, 1)
		s.mu.Lock()
		s.pendingTCP[clientID] = ch
		s.mu.Unlock()

		reqPkt := &protocol.Packet{
			Type:   protocol.TypeConnect,
			Route:  routeName,
			Client: clientID,
		}
		agent.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := protocol.WritePacket(agent, reqPkt); err != nil {
			conn.Close()
			s.mu.Lock()
			delete(s.pendingTCP, clientID)
			s.mu.Unlock()
			continue
		}
		agent.SetWriteDeadline(time.Time{})

		go func(c net.Conn, clientID string) {
			defer c.Close()
			select {
			case agentConn := <-ch:
				if agentConn == nil {
					return
				}
				defer agentConn.Close()
				s.dash.addConn(time.Now())
				s.dash.incActive(routeName)
				defer s.dash.decActive(routeName)

				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					n, _ := io.Copy(c, agentConn)
					s.dash.addBytes(time.Now(), n)
					c.Close()
					agentConn.Close()
				}()
				go func() {
					defer wg.Done()
					n, _ := io.Copy(agentConn, c)
					s.dash.addBytes(time.Now(), n)
					c.Close()
					agentConn.Close()
				}()
				wg.Wait()
			case <-time.After(s.cfg.PairTimeout):
				s.mu.Lock()
				delete(s.pendingTCP, clientID)
				s.mu.Unlock()
			}
		}(conn, clientID)
	}
}

func (s *Server) acceptAgentUDP() {
	defer s.wg.Done()
	defer s.udpDataConn.Close()

	buf := make([]byte, 65536)
	decryptBuf := make([]byte, 65536)
	var pkt protocol.Packet
	
	addrCacheMu := sync.RWMutex{}
	addrCache := make(map[string]*net.UDPAddr)

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

		// Update agent address to handle NAT port changes
		s.mu.Lock()
		if !s.agentUDP.IsValid() || s.agentUDP != addr {
			s.agentUDP = addr
			// Only log on register to avoid spam
			if pkt.Type == protocol.TypeRegister {
				logging.Global().Infof(logging.CatUDP, "Agent UDP address updated to %s", addr.String())
			}
		}
		s.mu.Unlock()

		if pkt.Type == protocol.TypeRegister {
			continue
		}

		if pkt.Type == protocol.TypeData {
			s.mu.RLock()
			pubConn, ok := s.publicUDP[pkt.Route]
			udpCipher := s.udpCipher
			s.mu.RUnlock()

			if !ok {
				continue
			}

			cache := s.routeCache.Load().(map[string]routeConfig)
			rc, ok := cache[pkt.Route]
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

			addrCacheMu.RLock()
			clientAddr, ok := addrCache[pkt.Client]
			addrCacheMu.RUnlock()

			if !ok {
				var err error
				clientAddr, err = net.ResolveUDPAddr("udp", pkt.Client)
				if err != nil {
					continue
				}
				addrCacheMu.Lock()
				if len(addrCache) > 10000 {
					addrCache = make(map[string]*net.UDPAddr)
				}
				// Copy string because it points to buf
				addrCache[string([]byte(pkt.Client))] = clientAddr
				addrCacheMu.Unlock()
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
			// Prevent cache from growing indefinitely
			if len(addrStrCache) > 10000 {
				addrStrCache = make(map[netip.AddrPort]string)
			}
			addrStrCache[addr] = clientStr
		}

		s.mu.RLock()
		agentAddr := s.agentUDP
		udpCipher := s.udpCipher
		s.mu.RUnlock()

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

		s.dash.addBytes(time.Now(), int64(len(pkt.Payload)))
		s.udpDataConn.WriteToUDPAddrPort(data, agentAddr)
	}
}
