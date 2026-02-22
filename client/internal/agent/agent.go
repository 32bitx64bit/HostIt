package agent

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/logging"
	"hostit/shared/protocol"
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

// Agent represents the tunnel agent.
type Agent struct {
	cfg   Config
	hooks *Hooks

	mu          sync.RWMutex
	controlConn net.Conn
	udpDataConn *net.UDPConn
	serverUDP   *net.UDPAddr

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewAgent creates a new tunnel agent.
func NewAgent(cfg Config) *Agent {
	return &Agent{
		cfg: cfg,
	}
}

// Start starts the tunnel agent.
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
			// Reconnect delay
		}
	}
}

func (a *Agent) connectAndRun() error {
	// Connect to control server
	var conn net.Conn
	var err error
	if a.cfg.DisableTLS {
		conn, err = net.Dial("tcp", a.cfg.ControlAddr())
	} else {
		tlsConfig := &tls.Config{InsecureSkipVerify: true} // TODO: implement pinning
		conn, err = tls.Dial("tcp", a.cfg.ControlAddr(), tlsConfig)
	}
	if err != nil {
		return fmt.Errorf("control dial failed: %w", err)
	}
	a.controlConn = conn
	defer conn.Close()

	// Authenticate
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(a.cfg.Token)); err != nil {
		return fmt.Errorf("control auth failed: %w", err)
	}
	conn.SetWriteDeadline(time.Time{})

	// Connect to UDP data server
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

	// Send initial registration
	pkt := &protocol.Packet{
		Type: protocol.TypeRegister,
	}
	data, _ := protocol.MarshalUDP(pkt)
	a.udpDataConn.WriteToUDP(data, a.serverUDP)

	logging.Global().Infof(logging.CatSystem, "Agent started on control=%s data=%s", a.cfg.ControlAddr(), a.cfg.DataAddr())

	if a.hooks != nil && a.hooks.OnConnected != nil {
		a.hooks.OnConnected()
	}

	// Create a sub-context for this connection
	connCtx, connCancel := context.WithCancel(a.ctx)
	defer connCancel()

	// Start UDP keep-alive (frequent to punch NAT and recover from packet loss)
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

	// Start TCP keep-alive
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypePing})
				conn.SetWriteDeadline(time.Time{})
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

	// Wait for either context cancellation or a critical goroutine to exit
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil && err != context.Canceled {
			return err
		}
	}
	return nil
}

// Stop stops the tunnel agent.
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
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			protocol.WritePacket(conn, &protocol.Packet{
				Type:    protocol.TypePong,
				Payload: pkt.Payload,
			})
			conn.SetWriteDeadline(time.Time{})
			continue
		}

		if pkt.Type == protocol.TypePong {
			continue
		}

		if pkt.Type == protocol.TypeHello {
			// Parse routes
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
			a.mu.Unlock()
			logging.Global().Infof(logging.CatSystem, "Received %d routes from server", len(routes))

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
				// Open data connection
				var dataConn net.Conn
				var err error
				if a.cfg.DisableTLS {
					dataConn, err = net.Dial("tcp", a.cfg.DataAddr())
				} else {
					tlsConfig := &tls.Config{InsecureSkipVerify: true}
					dataConn, err = tls.Dial("tcp", a.cfg.DataAddr(), tlsConfig)
				}
				if err != nil {
					return
				}

				// Authenticate and send route/client info in one write
				routeBytes := []byte(routeName)
				clientBytes := []byte(clientID)

				buf := make([]byte, 0, len(a.cfg.Token)+1+len(routeBytes)+1+len(clientBytes))
				buf = append(buf, []byte(a.cfg.Token)...)
				buf = append(buf, byte(len(routeBytes)))
				buf = append(buf, routeBytes...)
				buf = append(buf, byte(len(clientBytes)))
				buf = append(buf, clientBytes...)

				dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := dataConn.Write(buf); err != nil {
					dataConn.Close()
					return
				}
				dataConn.SetWriteDeadline(time.Time{})

				// Connect to local service
				_, port, _ := net.SplitHostPort(rt.PublicAddr)
				localAddr := "127.0.0.1:" + port
				localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
				if err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to dial local tcp %s: %v", localAddr, err)
					dataConn.Close()
					return
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

				// Proxy data
				go func() {
					io.Copy(localConn, dataConn)
					localConn.Close()
					dataConn.Close()
				}()
				go func() {
					io.Copy(dataConn, localConn)
					localConn.Close()
					dataConn.Close()
				}()
			}(routeName, clientID, rt)
		}
	}
}

type agentUDPSession struct {
	conn     *net.UDPConn
	lastSeen time.Time
}

func (a *Agent) handleUDPData(ctx context.Context) error {
	buf := make([]byte, 65536)

	var (
		sessionsMu sync.Mutex
		sessions   = make(map[string]*agentUDPSession)
	)

	// Cleanup idle sessions
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, _, err := a.udpDataConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("udp data read error: %w", err)
		}

		pkt, err := protocol.UnmarshalUDP(buf[:n])
		if err != nil {
			continue
		}

		if pkt.Type == protocol.TypeData {
			a.mu.RLock()
			rt, ok := a.cfg.Routes[pkt.Route]
			a.mu.RUnlock()

			if !ok {
				continue
			}

			payload := pkt.Payload
			if rt.Encrypted {
				udpCipher := rt.UDPCipher
				if udpCipher == nil {
					continue
				}
				decrypted, err := crypto.DecryptUDP(udpCipher, payload)
				if err != nil {
					continue
				}
				payload = decrypted
			}

			sessionKey := pkt.Route + "-" + pkt.Client

			sessionsMu.Lock()
			sess, exists := sessions[sessionKey]
			if exists {
				sess.lastSeen = time.Now()
			}
			sessionsMu.Unlock()

			if !exists {
				_, port, _ := net.SplitHostPort(rt.PublicAddr)
				localAddrStr := "127.0.0.1:" + port
				localAddr, err := net.ResolveUDPAddr("udp", localAddrStr)
				if err != nil {
					logging.Global().Errorf(logging.CatUDP, "failed to resolve local udp addr %s: %v", localAddrStr, err)
					continue
				}

				localConn, err := net.DialUDP("udp", nil, localAddr)
				if err != nil {
					logging.Global().Errorf(logging.CatUDP, "failed to dial local udp %s: %v", localAddrStr, err)
					continue
				}
				localConn.SetReadBuffer(8 * 1024 * 1024)
				localConn.SetWriteBuffer(8 * 1024 * 1024)

				sess = &agentUDPSession{
					conn:     localConn,
					lastSeen: time.Now(),
				}

				sessionsMu.Lock()
				sessions[sessionKey] = sess
				sessionsMu.Unlock()

				// Start reader for this session
				go func(sessionKey string, clientID string, routeName string, c *net.UDPConn, isEncrypted bool, udpCipher cipher.AEAD) {
					defer func() {
						c.Close()
						sessionsMu.Lock()
						delete(sessions, sessionKey)
						sessionsMu.Unlock()
					}()

					respBuf := make([]byte, 65536)
					for {
						c.SetReadDeadline(time.Now().Add(2 * time.Minute))
						rn, err := c.Read(respBuf)
						if err != nil {
							return
						}

						sessionsMu.Lock()
						s, ok := sessions[sessionKey]
						if ok {
							s.lastSeen = time.Now()
						}
						sessionsMu.Unlock()

						payload := respBuf[:rn]
						if isEncrypted {
							if udpCipher == nil {
								continue
							}
							encrypted, err := crypto.EncryptUDP(udpCipher, payload)
							if err != nil {
								continue
							}
							payload = encrypted
						}

						respPkt := &protocol.Packet{
							Type:    protocol.TypeData,
							Route:   routeName,
							Client:  clientID,
							Payload: payload,
						}

						data, err := protocol.MarshalUDP(respPkt)
						if err != nil {
							continue
						}

						a.udpDataConn.WriteToUDP(data, a.serverUDP)
					}
				}(sessionKey, pkt.Client, pkt.Route, localConn, rt.Encrypted, rt.UDPCipher)
			}

			sess.conn.Write(payload)
		}
	}
}
