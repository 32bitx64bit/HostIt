package agent

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/logging"
	"hostit/shared/netutil"
	"hostit/shared/protocol"
	"hostit/shared/relay"
)

type Hooks struct {
	OnConnected    func()
	OnRoutes       func(routes []RemoteRoute)
	OnDisconnected func(err error)
	OnError        func(err error)
}

func RunWithHooks(ctx context.Context, cfg Config, hooks *Hooks) error {
	a := &Agent{cfg: cfg, hooks: hooks}
	return a.Run(ctx)
}

type Agent struct {
	cfg   Config
	hooks *Hooks

	mu          sync.RWMutex
	controlConn net.Conn
	udpDataConn *net.UDPConn
	serverUDP   *net.UDPAddr

	controlWriteMu sync.Mutex
	routeCacheGen  uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewAgent(cfg Config) *Agent {
	return &Agent{
		cfg: cfg,
	}
}

func (a *Agent) Run(ctx context.Context) error {
	a.ctx, a.cancel = context.WithCancel(ctx)

	for {
		select {
		case <-a.ctx.Done():
			return nil
		default:
		}

		err := a.connectAndRun()
		if a.hooks != nil && a.hooks.OnDisconnected != nil {
			a.hooks.OnDisconnected(err)
		}
		if err != nil {
			logging.Global().Errorf(logging.CatSystem, "Agent error: %v", err)
		}

		select {
		case <-a.ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) connectAndRun() error {
	var conn net.Conn
	var err error
	controlDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
	if a.cfg.DisableTLS {
		conn, err = controlDialer.Dial("tcp", a.cfg.ControlAddr())
	} else {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}

		if a.cfg.TLSPinSHA256 != "" {
			tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("no certificates provided by server")
				}

				hash := sha256.Sum256(rawCerts[0])
				hashHex := hex.EncodeToString(hash[:])

				if !strings.EqualFold(hashHex, a.cfg.TLSPinSHA256) {
					return fmt.Errorf("certificate pinning failed: expected %s, got %s", a.cfg.TLSPinSHA256, hashHex)
				}
				return nil
			}
		}

		conn, err = tls.DialWithDialer(controlDialer, "tcp", a.cfg.ControlAddr(), tlsConfig)
	}
	if err != nil {
		return fmt.Errorf("control dial failed: %w", err)
	}
	netutil.SetTCPKeepAlive(conn, 15*time.Second)
	a.controlConn = conn
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := crypto.AuthenticateClient(conn, a.cfg.Token); err != nil {
		return fmt.Errorf("control auth failed: %w", err)
	}
	conn.SetDeadline(time.Time{})

	serverAddr, err := net.ResolveUDPAddr("udp", a.cfg.DataAddr())
	if err != nil {
		return fmt.Errorf("resolve udp data addr failed: %w", err)
	}
	a.serverUDP = serverAddr

	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return fmt.Errorf("resolve local udp addr failed: %w", err)
	}

	a.udpDataConn, err = net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("udp data listen failed: %w", err)
	}
	a.udpDataConn.SetReadBuffer(8 * 1024 * 1024)
	a.udpDataConn.SetWriteBuffer(8 * 1024 * 1024)
	defer a.udpDataConn.Close()

	pkt := &protocol.Packet{
		Type: protocol.TypeRegister,
	}
	data, _ := protocol.MarshalUDP(pkt, nil)
	a.udpDataConn.WriteToUDP(data, a.serverUDP)

	logging.Global().Infof(logging.CatSystem, "Agent started on control=%s data=%s", a.cfg.ControlAddr(), a.cfg.DataAddr())

	connCtx, connCancel := context.WithCancel(a.ctx)
	defer connCancel()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				a.udpDataConn.WriteToUDP(data, a.serverUDP)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				a.controlWriteMu.Lock()
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypePing})
				conn.SetWriteDeadline(time.Time{})
				a.controlWriteMu.Unlock()
			}
		}
	}()

	go func() {
		<-connCtx.Done()
		conn.Close()
		a.udpDataConn.Close()
	}()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer connCancel()
		if err := a.handleControl(connCtx, conn); err != nil {
			errCh <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer connCancel()
		if err := a.handleUDPData(connCtx); err != nil {
			errCh <- err
		}
	}()

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil && err != context.Canceled {
			return err
		}
	}
	return nil
}

func (a *Agent) Stop() {
	a.cancel()
	if a.controlConn != nil {
		a.controlConn.Close()
	}
	if a.udpDataConn != nil {
		a.udpDataConn.Close()
	}
	a.wg.Wait()
}

func (a *Agent) handleControl(ctx context.Context, conn net.Conn) error {
	helloSeen := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn.SetReadDeadline(time.Now().Add(45 * time.Second))
		pkt, err := protocol.ReadPacket(conn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("control read error: %w", err)
		}

		if pkt.Type == protocol.TypePing {
			a.controlWriteMu.Lock()
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			protocol.WritePacket(conn, &protocol.Packet{
				Type:    protocol.TypePong,
				Payload: pkt.Payload,
			})
			conn.SetWriteDeadline(time.Time{})
			a.controlWriteMu.Unlock()
			continue
		}

		if pkt.Type == protocol.TypePong {
			continue
		}

		if pkt.Type == protocol.TypeHello {
			var routes map[string]RemoteRoute
			if err := json.Unmarshal(pkt.Payload, &routes); err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to parse HELLO routes: %v", err)
				continue
			}
			for k, r := range routes {
				if r.Encrypted {
					key, err := crypto.DeriveKey(a.cfg.Token, r.Algorithm)
					if err != nil {
						logging.Global().Errorf(logging.CatTCP, "failed to derive key for route %s: %v", r.Name, err)
					} else {
						r.DerivedKey = key
						udpCipher, err := crypto.NewUDPCipher(key)
						if err != nil {
							logging.Global().Errorf(logging.CatTCP, "failed to create udp cipher for route %s: %v", r.Name, err)
						} else {
							r.UDPCipher = udpCipher
						}
						routes[k] = r
					}
				}
			}
			a.mu.Lock()
			a.cfg.Routes = routes
			a.routeCacheGen++
			a.mu.Unlock()
			logging.Global().Infof(logging.CatSystem, "Received %d routes from server", len(routes))
			if !helloSeen {
				helloSeen = true
				if a.hooks != nil && a.hooks.OnConnected != nil {
					a.hooks.OnConnected()
				}
			}

			if a.hooks != nil && a.hooks.OnRoutes != nil {
				var routeList []RemoteRoute
				for _, r := range routes {
					routeList = append(routeList, r)
				}
				a.hooks.OnRoutes(routeList)
			}
			continue
		}

		if pkt.Type == protocol.TypeConnect {
			routeName := pkt.Route
			clientID := pkt.Client

			a.mu.RLock()
			rt, ok := a.cfg.Routes[routeName]
			a.mu.RUnlock()

			if !ok {
				logging.Global().Errorf(logging.CatTCP, "unknown route requested: %s", routeName)
				continue
			}

			go func(routeName, clientID string, rt RemoteRoute) {
				var dataConn net.Conn
				var err error
				dialTimeout := 10 * time.Second
				dataDialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 15 * time.Second}
				if a.cfg.DisableTLS {
					dataConn, err = dataDialer.Dial("tcp", a.cfg.DataAddr())
				} else {
					tlsConfig := &tls.Config{InsecureSkipVerify: true}
					dataConn, err = tls.DialWithDialer(dataDialer, "tcp", a.cfg.DataAddr(), tlsConfig)
				}
				if err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to dial data server %s: %v", a.cfg.DataAddr(), err)
					return
				}
				netutil.SetTCPKeepAlive(dataConn, 15*time.Second)

				dataConn.SetDeadline(time.Now().Add(5 * time.Second))
				if err := crypto.AuthenticateClient(dataConn, a.cfg.Token); err != nil {
					logging.Global().Errorf(logging.CatTCP, "data auth failed: %v", err)
					dataConn.Close()
					return
				}

				routeBytes := []byte(routeName)
				clientBytes := []byte(clientID)

				buf := make([]byte, 0, 1+len(routeBytes)+1+len(clientBytes))
				buf = append(buf, byte(len(routeBytes)))
				buf = append(buf, routeBytes...)
				buf = append(buf, byte(len(clientBytes)))
				buf = append(buf, clientBytes...)

				dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := dataConn.Write(buf); err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to write route/client to data conn: %v", err)
					dataConn.Close()
					return
				}
				dataConn.SetDeadline(time.Time{})

				localAddr := rt.EffectiveLocalAddr()
				localConn, err := dialLocalTCP(localAddr)
				if err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to dial local tcp %s: %v", localAddr, err)
					dataConn.Close()
					return
				}

				if tcpConn, ok := localConn.(*net.TCPConn); ok {
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(15 * time.Second)
				}

				if rt.Encrypted {
					if rt.DerivedKey == nil {
						logging.Global().Errorf(logging.CatTCP, "failed to derive key for route %s: key is nil", routeName)
						dataConn.Close()
						localConn.Close()
						return
					}
					dataConn, err = crypto.WrapTCP(dataConn, rt.DerivedKey)
					if err != nil {
						logging.Global().Errorf(logging.CatTCP, "failed to wrap tcp for route %s: %v", routeName, err)
						dataConn.Close()
						localConn.Close()
						return
					}
				}

				relay.Proxy(localConn, dataConn)
			}(routeName, clientID, rt)
		}
	}
}

func dialLocalTCP(localAddr string) (net.Conn, error) {
	const (
		maxAttempts = 5
		dialTimeout = 2 * time.Second
		retryDelay  = 250 * time.Millisecond
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 15 * time.Second}
		conn, err := dialer.Dial("tcp", localAddr)
		if err == nil {
			netutil.SetTCPKeepAlive(conn, 15*time.Second)
			return conn, nil
		}
		lastErr = err
		if attempt < maxAttempts {
			time.Sleep(retryDelay)
		}
	}

	return nil, lastErr
}

type agentUDPSession struct {
	conn     *net.UDPConn
	lastSeen time.Time
}

func (a *Agent) handleUDPData(ctx context.Context) error {
	buf := make([]byte, 65536)
	decryptBuf := make([]byte, 65536)
	var pkt protocol.Packet

	type sessionKey struct {
		route  string
		client string
	}

	var (
		sessionsMu sync.Mutex
		sessions   = make(map[sessionKey]*agentUDPSession)
	)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				sessionsMu.Lock()
				for _, s := range sessions {
					s.conn.Close()
				}
				sessionsMu.Unlock()
				return
			case now := <-ticker.C:
				sessionsMu.Lock()
				for id, s := range sessions {
					if now.Sub(s.lastSeen) > 2*time.Minute {
						s.conn.Close()
						delete(sessions, id)
					}
				}
				sessionsMu.Unlock()
			}
		}
	}()

	type routeConfig struct {
		isEncrypted bool
		udpCipher   cipher.AEAD
		localAddr   string
	}
	var routeCache sync.Map
	var lastCacheGen uint64

	rebuildRouteCache := func() {
		routeCache = sync.Map{}
		a.mu.RLock()
		lastCacheGen = a.routeCacheGen
		for _, rt := range a.cfg.Routes {
			routeCache.Store(rt.Name, routeConfig{
				isEncrypted: rt.Encrypted,
				udpCipher:   rt.UDPCipher,
				localAddr:   rt.EffectiveLocalAddr(),
			})
		}
		a.mu.RUnlock()
	}

	refreshRouteCacheIfNeeded := func() {
		a.mu.RLock()
		currentCacheGen := a.routeCacheGen
		a.mu.RUnlock()
		if currentCacheGen != lastCacheGen {
			rebuildRouteCache()
		}
	}

	rebuildRouteCache()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		refreshRouteCacheIfNeeded()

		n, _, err := a.udpDataConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logging.Global().Errorf(logging.CatUDP, "udp data read error: %v", err)
			continue
		}

		err = protocol.UnmarshalUDPTo(buf[:n], &pkt)
		if err != nil {
			continue
		}

		if pkt.Type == protocol.TypeData {
			refreshRouteCacheIfNeeded()

			routeName := string([]byte(pkt.Route))
			clientID := string([]byte(pkt.Client))

			rcVal, ok := routeCache.Load(routeName)
			var rc routeConfig
			if !ok {
				a.mu.RLock()
				rt, ok := a.cfg.Routes[routeName]
				a.mu.RUnlock()
				if !ok {
					continue
				}
				rc = routeConfig{
					isEncrypted: rt.Encrypted,
					udpCipher:   rt.UDPCipher,
					localAddr:   rt.EffectiveLocalAddr(),
				}
				routeCache.Store(routeName, rc)
			} else {
				rc = rcVal.(routeConfig)
			}

			payload := pkt.Payload
			if rc.isEncrypted {
				udpCipher := rc.udpCipher
				if udpCipher == nil {
					continue
				}
				decrypted, err := crypto.DecryptUDP(udpCipher, decryptBuf, payload)
				if err != nil {
					continue
				}
				payload = decrypted
			}

			key := sessionKey{route: routeName, client: clientID}

			sessionsMu.Lock()
			sess, exists := sessions[key]
			if exists {
				sess.lastSeen = time.Now()
			}
			sessionsMu.Unlock()

			if !exists {
				localAddr, err := net.ResolveUDPAddr("udp", rc.localAddr)
				if err != nil {
					logging.Global().Errorf(logging.CatUDP, "failed to resolve local udp addr %s: %v", rc.localAddr, err)
					continue
				}

				localConn, err := net.DialUDP("udp", nil, localAddr)
				if err != nil {
					logging.Global().Errorf(logging.CatUDP, "failed to dial local udp %s: %v", rc.localAddr, err)
					continue
				}
				localConn.SetReadBuffer(8 * 1024 * 1024)
				localConn.SetWriteBuffer(8 * 1024 * 1024)

				sess = &agentUDPSession{
					conn:     localConn,
					lastSeen: time.Now(),
				}

				sessionsMu.Lock()
				sessions[key] = sess
				sessionsMu.Unlock()

				go func(key sessionKey, c *net.UDPConn, isEncrypted bool, udpCipher cipher.AEAD) {
					defer func() {
						c.Close()
						sessionsMu.Lock()
						delete(sessions, key)
						sessionsMu.Unlock()
					}()

					respBuf := make([]byte, 65536)
					marshalBuf := make([]byte, 65536)
					encryptBuf := make([]byte, 65536)
					var respPkt protocol.Packet
					for {
						select {
						case <-ctx.Done():
							return
						default:
						}

						c.SetReadDeadline(time.Now().Add(2 * time.Minute))
						rn, err := c.Read(respBuf)
						if err != nil {
							if ctx.Err() != nil {
								return
							}
							return
						}

						sessionsMu.Lock()
						s, ok := sessions[key]
						if ok {
							s.lastSeen = time.Now()
						}
						sessionsMu.Unlock()

						payload := respBuf[:rn]
						if isEncrypted {
							if udpCipher == nil {
								continue
							}
							encrypted, err := crypto.EncryptUDP(udpCipher, encryptBuf, payload)
							if err != nil {
								continue
							}
							payload = encrypted
						}

						respPkt.Type = protocol.TypeData
						respPkt.Route = key.route
						respPkt.Client = key.client
						respPkt.Payload = payload

						data, err := protocol.MarshalUDP(&respPkt, marshalBuf)
						if err != nil {
							continue
						}

						a.udpDataConn.WriteToUDP(data, a.serverUDP)
					}
				}(key, localConn, rc.isEncrypted, rc.udpCipher)
			}

			var sessConn *net.UDPConn
			sessionsMu.Lock()
			if s, ok := sessions[key]; ok && s.conn != nil {
				s.lastSeen = time.Now()
				sessConn = s.conn
			}
			sessionsMu.Unlock()
			if sessConn != nil {
				_, _ = sessConn.Write(payload)
			}
		}
	}
}
