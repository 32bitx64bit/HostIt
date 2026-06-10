package agent

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"hostit/shared/apitypes"
	"hostit/shared/crypto"
	"hostit/shared/emailcfg"
	"hostit/shared/logging"
	"hostit/shared/netutil"
	"hostit/shared/protocol"
	"hostit/shared/relay"
)

const (
	agentControlPingInterval  = 5 * time.Second
	agentControlReadDeadline  = 45 * time.Second
	agentControlWriteDeadline = 5 * time.Second
	udpRegisterInterval       = 2 * time.Second
	udpSessionIdleTimeout     = 2 * time.Minute
)

type Hooks struct {
	OnConnected        func()
	OnEmailConfig      func(cfg emailcfg.Config)
	OnEmailProbe       func(context.Context, protocol.EmailProbeRequest) (protocol.EmailProbeResult, error)
	OnRoutes           func(routes []RemoteRoute)
	OnRouteResponse    func(apitypes.RouteResponse)
	OnRouteAck         func(apitypes.RouteAck)
	OnRouteRemoveAck   func(apitypes.RouteRemoveAck)
	OnDisconnected     func(err error)
	OnError            func(err error)
	OnTLSPinDiscovered func(pin string)
}

type helloPayload struct {
	Routes map[string]RemoteRoute `json:"routes"`
	Email  emailcfg.Config        `json:"email,omitempty"`
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
	routeCacheGen  atomic.Uint64

	pendingRouteReqs  map[string]chan *apitypes.RouteResponse
	pendingRouteAcks  map[string]chan *apitypes.RouteAck
	pendingRemoveAcks map[string]chan *apitypes.RouteRemoveAck
	pendingUpdateAcks map[string]chan *apitypes.RouteUpdateAck

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// connTracker keeps track of all TCP relay connections for the current
// control session so they can be forcibly closed when the session ends.
type connTracker struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func (ct *connTracker) add(c net.Conn) {
	ct.mu.Lock()
	if ct.closed {
		ct.mu.Unlock()
		_ = c.Close()
		return
	}
	if ct.conns == nil {
		ct.conns = make(map[net.Conn]struct{})
	}
	ct.conns[c] = struct{}{}
	ct.mu.Unlock()
}

func (ct *connTracker) remove(c net.Conn) {
	ct.mu.Lock()
	delete(ct.conns, c)
	ct.mu.Unlock()
}

func (ct *connTracker) closeAll() {
	ct.mu.Lock()
	conns := ct.conns
	ct.conns = nil
	ct.closed = true
	ct.mu.Unlock()
	for c := range conns {
		_ = c.Close()
	}
}

func NewAgent(cfg Config) *Agent {
	return &Agent{
		cfg:               cfg,
		pendingRouteReqs:  make(map[string]chan *apitypes.RouteResponse),
		pendingRouteAcks:  make(map[string]chan *apitypes.RouteAck),
		pendingRemoveAcks: make(map[string]chan *apitypes.RouteRemoveAck),
		pendingUpdateAcks: make(map[string]chan *apitypes.RouteUpdateAck),
	}
}

func (a *Agent) SetHooks(hooks *Hooks) {
	a.hooks = hooks
}

func (a *Agent) ControlConn() net.Conn {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.controlConn
}

// sendAndWait marshals payload, sends a control packet, and waits up to
// 30s for a response on the pending channel. It handles map registration,
// cleanup, write deadlines, and context cancellation. Used by all
// SendRoute* methods to eliminate the duplicated marshal+lock+write+select
// boilerplate (CLEAN-5).
func sendAndWait[Resp any](ctx context.Context, a *Agent,
	pending map[string]chan *Resp, key string,
	pktType byte, payload []byte, timeoutMsg string) (*Resp, error) {

	ch := make(chan *Resp, 1)
	a.mu.Lock()
	pending[key] = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(pending, key)
		a.mu.Unlock()
	}()

	a.controlWriteMu.Lock()
	conn := a.controlConn
	if conn == nil {
		a.controlWriteMu.Unlock()
		return nil, fmt.Errorf("not connected to server")
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: pktType, Payload: payload}); err != nil {
		conn.SetWriteDeadline(time.Time{})
		a.controlWriteMu.Unlock()
		return nil, err
	}
	conn.SetWriteDeadline(time.Time{})
	a.controlWriteMu.Unlock()

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("%s", timeoutMsg)
	}
}

func (a *Agent) SendRouteRequest(ctx context.Context, req apitypes.RouteRequest) (*apitypes.RouteResponse, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return sendAndWait(ctx, a, a.pendingRouteReqs, req.RequestID, protocol.TypeRouteRequest, payload, "route request timed out")
}

func (a *Agent) SendRouteConfirm(ctx context.Context, confirm apitypes.RouteConfirm) (*apitypes.RouteAck, error) {
	payload, err := json.Marshal(confirm)
	if err != nil {
		return nil, err
	}
	return sendAndWait(ctx, a, a.pendingRouteAcks, confirm.RequestID, protocol.TypeRouteConfirm, payload, "route confirm timed out")
}

func (a *Agent) SendRouteRemove(ctx context.Context, remove apitypes.RouteRemove) (*apitypes.RouteRemoveAck, error) {
	payload, err := json.Marshal(remove)
	if err != nil {
		return nil, err
	}
	return sendAndWait(ctx, a, a.pendingRemoveAcks, remove.Name, protocol.TypeRouteRemove, payload, "route remove timed out")
}

func (a *Agent) SendRouteUpdate(ctx context.Context, update apitypes.RouteUpdate) (*apitypes.RouteUpdateAck, error) {
	payload, err := json.Marshal(update)
	if err != nil {
		return nil, err
	}
	return sendAndWait(ctx, a, a.pendingUpdateAcks, update.RequestID, protocol.TypeRouteUpdate, payload, "route update timed out")
}

// tlsConfigWithPin returns a TLS config that performs certificate pinning
// when a SHA-256 pin is configured. When no pin is configured, the agent
// requires InsecureTLS to be explicitly set, or it returns an error.
func tlsConfigWithPin(cfg Config) (*tls.Config, error) {
	if pin := strings.TrimSpace(cfg.TLSPinSHA256); pin != "" {
		expectedPin := pin
		return &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("no certificates provided by server")
				}
				hash := sha256.Sum256(rawCerts[0])
				hashHex := hex.EncodeToString(hash[:])
				if !strings.EqualFold(hashHex, expectedPin) {
					return fmt.Errorf("certificate pinning failed: expected %s, got %s", expectedPin, hashHex)
				}
				return nil
			},
		}, nil
	}
	if cfg.InsecureTLS {
		logging.Global().Warnf(logging.CatEncryption, "TLS certificate verification is disabled (InsecureTLS=true). This is vulnerable to MITM attacks. Set tls_pin_sha256 for secure pinning.")
		return &tls.Config{InsecureSkipVerify: true}, nil
	}
	return nil, fmt.Errorf("TLS is enabled but no certificate pin is configured. Set tls_pin_sha256 to the server certificate SHA-256 fingerprint, or set InsecureTLS=true to explicitly accept any certificate (not recommended)")
}

func (a *Agent) Run(ctx context.Context) error {
	a.ctx, a.cancel = context.WithCancel(ctx)
	if err := a.startUDPData(a.ctx); err != nil {
		return err
	}
	defer a.closeUDPDataConn()

	backoff := 250 * time.Millisecond
	const maxBackoff = 2 * time.Second

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
		case <-time.After(backoff):
		}

		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (a *Agent) startUDPData(ctx context.Context) error {
	serverAddr, err := net.ResolveUDPAddr("udp", a.cfg.DataAddr())
	if err != nil {
		return fmt.Errorf("resolve udp data addr failed: %w", err)
	}

	localAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return fmt.Errorf("resolve local udp addr failed: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("udp data listen failed: %w", err)
	}
	udpConn.SetReadBuffer(8 * 1024 * 1024)
	udpConn.SetWriteBuffer(8 * 1024 * 1024)

	a.mu.Lock()
	a.serverUDP = serverAddr
	a.udpDataConn = udpConn
	a.mu.Unlock()

	a.sendUDPRegister(udpConn)

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(udpRegisterInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.sendUDPRegister(udpConn)
			}
		}
	}()

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.handleUDPData(ctx, udpConn); err != nil && err != context.Canceled {
			logging.Global().Errorf(logging.CatUDP, "udp data loop stopped: %v", err)
		}
	}()

	return nil
}

func (a *Agent) closeUDPDataConn() {
	a.mu.Lock()
	udpConn := a.udpDataConn
	if udpConn != nil {
		a.udpDataConn = nil
	}
	a.mu.Unlock()
	if udpConn != nil {
		udpConn.Close()
	}
}

// sendUDPRegister builds a fresh token-authenticated register payload and
// sends it to the server. A new payload is generated on every call (the
// authenticator binds a fresh timestamp + nonce), so it must not be cached
// across sends (SEC-3).
func (a *Agent) sendUDPRegister(udpConn *net.UDPConn) {
	a.mu.RLock()
	serverUDP := a.serverUDP
	token := a.cfg.Token
	a.mu.RUnlock()
	if serverUDP == nil {
		return
	}
	authPayload, err := crypto.BuildUDPRegister(token)
	if err != nil {
		logging.Global().RateLimitedError(logging.CatUDP, "agent-udp-register-auth", fmt.Sprintf("failed to build UDP register auth: %v", err))
		return
	}
	data, err := protocol.MarshalUDP(&protocol.Packet{Type: protocol.TypeRegister, Payload: authPayload}, nil)
	if err != nil {
		logging.Global().RateLimitedError(logging.CatUDP, "agent-udp-register-marshal", fmt.Sprintf("failed to marshal UDP register: %v", err))
		return
	}
	n, err := udpConn.WriteToUDP(data, serverUDP)
	if err != nil {
		logging.Global().RateLimitedError(logging.CatUDP, "agent-udp-register-write", fmt.Sprintf("failed to send UDP register: %v", err))
		return
	}
	if n != len(data) {
		logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-register-short-write", fmt.Sprintf("short UDP register write: wrote=%d want=%d", n, len(data)))
	}
}

func (a *Agent) refreshUDPRegistration() {
	a.mu.RLock()
	udpConn := a.udpDataConn
	a.mu.RUnlock()
	if udpConn == nil {
		return
	}
	a.sendUDPRegister(udpConn)
}

func (a *Agent) connectAndRun() error {
	var conn net.Conn
	var err error
	controlDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
	if a.cfg.DisableTLS {
		conn, err = controlDialer.Dial("tcp", a.cfg.ControlAddr())
	} else {
		var tlsCfg *tls.Config
		if a.cfg.TLSPinSHA256 == "" && !a.cfg.InsecureTLS {
			// Auto-pin: connect permissively once to capture the server's cert fingerprint.
			tlsCfg = &tls.Config{InsecureSkipVerify: true}
		} else {
			var tlsErr error
			tlsCfg, tlsErr = tlsConfigWithPin(a.cfg)
			if tlsErr != nil {
				return fmt.Errorf("tls config failed: %w", tlsErr)
			}
		}
		conn, err = tls.DialWithDialer(controlDialer, "tcp", a.cfg.ControlAddr(), tlsCfg)
		if err == nil && a.cfg.TLSPinSHA256 == "" && !a.cfg.InsecureTLS {
			if tlsConn, ok := conn.(*tls.Conn); ok {
				state := tlsConn.ConnectionState()
				if len(state.PeerCertificates) > 0 {
					pin := sha256.Sum256(state.PeerCertificates[0].Raw)
					pinHex := hex.EncodeToString(pin[:])
					a.cfg.TLSPinSHA256 = pinHex
					if a.hooks != nil && a.hooks.OnTLSPinDiscovered != nil {
						a.hooks.OnTLSPinDiscovered(pinHex)
					}
					logging.Global().Infof(logging.CatEncryption, "Auto-pinned server TLS certificate SHA-256: %s", pinHex)
				}
			}
		}
	}
	if err != nil {
		return fmt.Errorf("control dial failed: %w", err)
	}
	netutil.SetTCPKeepAlive(conn, 15*time.Second)
	netutil.SetTCPNoDelay(conn)
	a.mu.Lock()
	a.controlConn = conn
	a.mu.Unlock()
	defer func() {
		conn.Close()
		a.mu.Lock()
		if a.controlConn == conn {
			a.controlConn = nil
		}
		a.mu.Unlock()
	}()

	conn.SetDeadline(time.Now().Add(agentControlWriteDeadline))
	_, _, err = crypto.AuthenticateClient(conn, a.cfg.Token)
	if err != nil {
		return fmt.Errorf("control auth failed: %w", err)
	}
	conn.SetDeadline(time.Time{})
	a.refreshUDPRegistration()

	logging.Global().Infof(logging.CatSystem, "Agent control connected on %s data=%s", a.cfg.ControlAddr(), a.cfg.DataAddr())

	connCtx, connCancel := context.WithCancel(a.ctx)
	defer connCancel()

	go func() {
		ticker := time.NewTicker(agentControlPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				a.controlWriteMu.Lock()
				conn.SetWriteDeadline(time.Now().Add(agentControlWriteDeadline))
				if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypePing}); err != nil {
					a.controlWriteMu.Unlock()
					conn.Close()
					return
				}
				conn.SetWriteDeadline(time.Time{})
				a.controlWriteMu.Unlock()
			}
		}
	}()

	go func() {
		<-connCtx.Done()
		conn.Close()
	}()

	tracker := &connTracker{}
	go func() {
		<-connCtx.Done()
		tracker.closeAll()
	}()

	var (
		errCh = make(chan error, 1)
		wg    sync.WaitGroup
	)

	wg.Add(1)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer wg.Done()
		defer connCancel()
		if err := a.handleControl(connCtx, conn, tracker); err != nil {
			select {
			case errCh <- err:
			default:
			}
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
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Lock()
	if a.controlConn != nil {
		a.controlConn.Close()
		a.controlConn = nil
	}
	if a.udpDataConn != nil {
		a.udpDataConn.Close()
		a.udpDataConn = nil
	}
	a.mu.Unlock()
	a.wg.Wait()
}

func (a *Agent) EmailConfig() emailcfg.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return emailcfg.Normalize(a.cfg.Email)
}

func (a *Agent) handleControl(ctx context.Context, conn net.Conn, tracker *connTracker) error {
	helloSeen := false
	var pkt protocol.Packet
	deadlineAt := time.Now().Add(agentControlReadDeadline)
	conn.SetReadDeadline(deadlineAt)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := protocol.ReadPacketTo(conn, &pkt); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("control read error: %w", err)
		}
		deadlineAt = time.Now().Add(agentControlReadDeadline)
		conn.SetReadDeadline(deadlineAt)

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

		if pkt.Type == protocol.TypeEmailProbeRequest {
			var req protocol.EmailProbeRequest
			if err := json.Unmarshal(pkt.Payload, &req); err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to parse email probe request: %v", err)
				continue
			}
			go func(req protocol.EmailProbeRequest) {
				res := protocol.EmailProbeResult{}
				if a.hooks == nil || a.hooks.OnEmailProbe == nil {
					res.Error = "email probe handler not configured"
				} else {
					probeRes, err := a.hooks.OnEmailProbe(ctx, req)
					res = probeRes
					if err != nil && res.Error == "" {
						res.Error = err.Error()
					}
				}
				payload, err := json.Marshal(res)
				if err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to marshal email probe result: %v", err)
					return
				}
				a.controlWriteMu.Lock()
				defer a.controlWriteMu.Unlock()
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeEmailProbeResult, Payload: payload}); err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to send email probe result: %v", err)
				}
				conn.SetWriteDeadline(time.Time{})
			}(req)
			continue
		}

		if pkt.Type == protocol.TypeHello {
			var (
				routes map[string]RemoteRoute
				email  emailcfg.Config
			)
			var hello helloPayload
			if err := json.Unmarshal(pkt.Payload, &hello); err == nil && hello.Routes != nil {
				routes = hello.Routes
				email = emailcfg.Normalize(hello.Email)
			} else if err := json.Unmarshal(pkt.Payload, &routes); err != nil {
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
			a.cfg.Email = email
			a.mu.Unlock()
			a.routeCacheGen.Add(1)
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
			if a.hooks != nil && a.hooks.OnEmailConfig != nil {
				a.hooks.OnEmailConfig(email)
			}
			continue
		}

		if pkt.Type == protocol.TypeRouteResponse {
			var resp apitypes.RouteResponse
			if err := json.Unmarshal(pkt.Payload, &resp); err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to parse route response: %v", err)
				continue
			}
			a.mu.Lock()
			if ch, ok := a.pendingRouteReqs[resp.RequestID]; ok {
				ch <- &resp
			}
			a.mu.Unlock()
			if a.hooks != nil && a.hooks.OnRouteResponse != nil {
				a.hooks.OnRouteResponse(resp)
			}
			continue
		}

		if pkt.Type == protocol.TypeRouteAck {
			var ack apitypes.RouteAck
			if err := json.Unmarshal(pkt.Payload, &ack); err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to parse route ack: %v", err)
				continue
			}
			a.mu.Lock()
			if ch, ok := a.pendingRouteAcks[ack.RequestID]; ok {
				ch <- &ack
			}
			a.mu.Unlock()
			if a.hooks != nil && a.hooks.OnRouteAck != nil {
				a.hooks.OnRouteAck(ack)
			}
			continue
		}

		if pkt.Type == protocol.TypeRouteRemoveAck {
			var ack apitypes.RouteRemoveAck
			if err := json.Unmarshal(pkt.Payload, &ack); err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to parse route remove ack: %v", err)
				continue
			}
			a.mu.Lock()
			if ch, ok := a.pendingRemoveAcks[ack.Name]; ok {
				ch <- &ack
			}
			a.mu.Unlock()
			if a.hooks != nil && a.hooks.OnRouteRemoveAck != nil {
				a.hooks.OnRouteRemoveAck(ack)
			}
			continue
		}

		if pkt.Type == protocol.TypeRouteUpdateAck {
			var ack apitypes.RouteUpdateAck
			if err := json.Unmarshal(pkt.Payload, &ack); err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to parse route update ack: %v", err)
				continue
			}
			a.mu.Lock()
			if ch, ok := a.pendingUpdateAcks[ack.RequestID]; ok {
				ch <- &ack
			}
			a.mu.Unlock()
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

			a.wg.Add(1)
			go func(ctx context.Context, routeName, clientID string, rt RemoteRoute) {
				defer a.wg.Done()

				select {
				case <-ctx.Done():
					return
				default:
				}

				var dataConn net.Conn
				var err error
				dialTimeout := 10 * time.Second
				dataDialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 15 * time.Second}
				if a.cfg.DisableTLS {
					dataConn, err = dataDialer.Dial("tcp", a.cfg.DataAddr())
				} else {
					tlsCfg, tlsErr := tlsConfigWithPin(a.cfg)
					if tlsErr != nil {
						logging.Global().Errorf(logging.CatTCP, "tls config failed: %v", tlsErr)
						return
					}
					dataConn, err = tls.DialWithDialer(dataDialer, "tcp", a.cfg.DataAddr(), tlsCfg)
				}
				if err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to dial data server %s: %v", a.cfg.DataAddr(), err)
					return
				}
				netutil.SetTCPKeepAlive(dataConn, 15*time.Second)
				netutil.SetTCPNoDelay(dataConn)
				netutil.TuneDeadPeerDetection(dataConn)

				dataConn.SetDeadline(time.Now().Add(5 * time.Second))
				clientNonce, serverNonce, err := crypto.AuthenticateClient(dataConn, a.cfg.Token)
				if err != nil {
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

				select {
				case <-ctx.Done():
					dataConn.Close()
					return
				default:
				}

				localAddr := rt.EffectiveLocalAddr()
				localConn, err := dialLocalTCP(ctx, localAddr)
				if err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to dial local tcp %s: %v", localAddr, err)
					dataConn.Close()
					return
				}

				select {
				case <-ctx.Done():
					dataConn.Close()
					localConn.Close()
					return
				default:
				}

				// dialLocalTCP already sets TCP keepalive and NoDelay.
				netutil.TuneDeadPeerDetection(localConn)

				if rt.Encrypted {
					if rt.DerivedKey == nil {
						logging.Global().Errorf(logging.CatTCP, "failed to derive key for route %s: key is nil", routeName)
						dataConn.Close()
						localConn.Close()
						return
					}
					dataConn, err = crypto.WrapTCP(dataConn, rt.DerivedKey, clientNonce, serverNonce, true)
					if err != nil {
						logging.Global().Errorf(logging.CatTCP, "failed to wrap tcp for route %s: %v", routeName, err)
						dataConn.Close()
						localConn.Close()
						return
					}
				}

				select {
				case <-ctx.Done():
					dataConn.Close()
					localConn.Close()
					return
				default:
				}

				tracker.add(dataConn)
				tracker.add(localConn)
				relay.ProxyWithIdleTimeout(localConn, dataConn, 5*time.Minute)
				tracker.remove(dataConn)
				tracker.remove(localConn)
			}(ctx, routeName, clientID, rt)
		}
	}
}

func dialLocalTCP(ctx context.Context, localAddr string) (net.Conn, error) {
	const (
		maxAttempts = 5
		dialTimeout = 2 * time.Second
		retryDelay  = 250 * time.Millisecond
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 15 * time.Second}
		conn, err := dialer.Dial("tcp", localAddr)
		if err == nil {
			netutil.SetTCPKeepAlive(conn, 15*time.Second)
			netutil.SetTCPNoDelay(conn)
			return conn, nil
		}
		lastErr = err
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay):
			}
		}
	}

	return nil, lastErr
}

func DialMailOutboundTCP(ctx context.Context, cfg Config, remoteAddr string) (net.Conn, error) {
	remoteAddr = strings.TrimSpace(remoteAddr)
	resolved, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil || resolved == nil {
		return nil, fmt.Errorf("resolve outbound SMTP target %q: %w", remoteAddr, err)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
	var dataConn net.Conn
	if cfg.DisableTLS {
		dataConn, err = dialer.DialContext(ctx, "tcp", cfg.DataAddr())
	} else {
		// Require a verified TLS configuration. Unlike the control channel,
		// this path runs without an Agent to persist a discovered pin, so a
		// trust-on-first-use here would silently run unverified forever (the
		// pin was only ever written to a by-value cfg copy). Demand that the
		// pin has already been established via the control connection (SEC-6).
		tlsCfg, tlsErr := tlsConfigWithPin(cfg)
		if tlsErr != nil {
			return nil, fmt.Errorf("tls config failed: %w", tlsErr)
		}
		dataConn, err = tls.DialWithDialer(dialer, "tcp", cfg.DataAddr(), tlsCfg)
	}
	if err != nil {
		return nil, fmt.Errorf("dial data server %s: %w", cfg.DataAddr(), err)
	}
	netutil.SetTCPKeepAlive(dataConn, 15*time.Second)
	netutil.SetTCPNoDelay(dataConn)

	if err := dataConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		dataConn.Close()
		return nil, err
	}
	if _, _, err := crypto.AuthenticateClient(dataConn, cfg.Token); err != nil {
		dataConn.Close()
		return nil, fmt.Errorf("data auth failed: %w", err)
	}

	routeBytes := []byte(protocol.RouteMailOutboundTCP)
	targetBytes := []byte(resolved.String())
	if len(targetBytes) > 255 {
		dataConn.Close()
		return nil, fmt.Errorf("outbound SMTP target %q is too long", resolved.String())
	}
	buf := make([]byte, 0, 1+len(routeBytes)+1+len(targetBytes))
	buf = append(buf, byte(len(routeBytes)))
	buf = append(buf, routeBytes...)
	buf = append(buf, byte(len(targetBytes)))
	buf = append(buf, targetBytes...)
	if _, err := dataConn.Write(buf); err != nil {
		dataConn.Close()
		return nil, fmt.Errorf("write outbound SMTP target: %w", err)
	}
	if err := dataConn.SetDeadline(time.Time{}); err != nil {
		dataConn.Close()
		return nil, err
	}
	return dataConn, nil
}

type agentUDPSession struct {
	conn     *net.UDPConn
	lastSeen int64 // atomic, unix nano
}

func shouldRetireUDPReadSession(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return !isTransientUDPReadError(err)
}

func isTransientUDPReadError(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENOBUFS)
}

// normalizeAddrPort unmaps IPv4-in-IPv6 addresses so that addresses obtained
// from net.ResolveUDPAddr and from ReadFromUDPAddrPort compare equal when they
// refer to the same endpoint.
func normalizeAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (a *Agent) handleUDPData(ctx context.Context, udpConn *net.UDPConn) error {
	buf := make([]byte, 65536)
	decryptBuf := make([]byte, 65536)
	var pkt protocol.Packet

	// Only datagrams originating from the server's data address are honored;
	// anything else on this socket is a spoof/injection attempt against local
	// services and is dropped (SEC-4). serverUDP is set once before this loop
	// starts and is stable for the agent's lifetime.
	a.mu.RLock()
	serverUDP := a.serverUDP
	a.mu.RUnlock()
	var serverAP netip.AddrPort
	if serverUDP != nil {
		serverAP = normalizeAddrPort(serverUDP.AddrPort())
	}

	type sessionKey struct {
		route  string
		client string
	}

	var sessions sync.Map

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				sessions.Range(func(_, v any) bool {
					v.(*agentUDPSession).conn.Close()
					return true
				})
				return
			case now := <-ticker.C:
				cutoff := now.Add(-2 * time.Minute).UnixNano()
				sessions.Range(func(k, v any) bool {
					sess := v.(*agentUDPSession)
					if atomic.LoadInt64(&sess.lastSeen) < cutoff {
						sess.conn.Close()
						sessions.Delete(k)
					}
					return true
				})
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
		lastCacheGen = a.routeCacheGen.Load()
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
		currentCacheGen := a.routeCacheGen.Load()
		if currentCacheGen != lastCacheGen {
			rebuildRouteCache()
		}
	}

	rebuildRouteCache()

	for {
		n, from, err := udpConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logging.Global().Errorf(logging.CatUDP, "udp data read error: %v", err)
			continue
		}

		if serverAP.IsValid() && normalizeAddrPort(from) != serverAP {
			logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-foreign-source", fmt.Sprintf("dropping UDP datagram from non-server source %s", from))
			continue
		}

		refreshRouteCacheIfNeeded()

		err = protocol.UnmarshalUDPTo(buf[:n], &pkt)
		if err != nil {
			continue
		}

		if pkt.Type == protocol.TypeData {
			routeName := pkt.Route
			clientID := pkt.Client

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

			sessVal, exists := sessions.Load(key)
			if exists {
				atomic.StoreInt64(&sessVal.(*agentUDPSession).lastSeen, time.Now().UnixNano())
			} else {
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

				newSess := &agentUDPSession{
					conn:     localConn,
					lastSeen: time.Now().UnixNano(),
				}

				actual, loaded := sessions.LoadOrStore(key, newSess)
				if loaded {
					localConn.Close()
					sessVal = actual
				} else {
					sessVal = newSess

					go func(key sessionKey, sess *agentUDPSession, c *net.UDPConn, isEncrypted bool, udpCipher cipher.AEAD) {
						defer func() {
							c.Close()
							sessions.CompareAndDelete(key, sess)
						}()

						respBuf := make([]byte, 65536)
						marshalBuf := make([]byte, 65536)
						encryptBuf := make([]byte, 65536)
						var respPkt protocol.Packet
						respPkt.Type = protocol.TypeData
						respPkt.Route = key.route
						respPkt.Client = key.client
						for {
							c.SetReadDeadline(time.Now().Add(2 * time.Minute))
							rn, err := c.Read(respBuf)
							if err != nil {
								if ctx.Err() != nil {
									return
								}
								if shouldRetireUDPReadSession(err) {
									logging.Global().Debugf(logging.CatUDP, "retiring UDP session route=%s client=%s err=%v", key.route, key.client, err)
									return
								}
								logging.Global().RateLimitedWarn(logging.CatUDP, "agent-local-udp-transient-"+key.route, fmt.Sprintf("transient local UDP read error route=%s client=%s err=%v", key.route, key.client, err))
								continue
							}

							if sessVal, ok := sessions.Load(key); ok {
								atomic.StoreInt64(&sessVal.(*agentUDPSession).lastSeen, time.Now().UnixNano())
							}

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

							respPkt.Payload = payload

							data, err := protocol.MarshalUDP(&respPkt, marshalBuf)
							if err != nil {
								logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-marshal-"+key.route, fmt.Sprintf("failed to marshal UDP response route=%s client=%s payload=%d err=%v", key.route, key.client, len(payload), err))
								continue
							}

							warnLargeTunneledUDPDatagram("agent-to-server", key.route, key.client, len(data))
							n, err := udpConn.WriteToUDP(data, a.serverUDP)
							if err != nil {
								logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-write-server-"+key.route, fmt.Sprintf("failed to write UDP response to server route=%s client=%s bytes=%d err=%v", key.route, key.client, len(data), err))
								continue
							}
							if n != len(data) {
								logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-short-write-server-"+key.route, fmt.Sprintf("short UDP response write to server route=%s client=%s wrote=%d want=%d", key.route, key.client, n, len(data)))
							}
						}
					}(key, newSess, localConn, rc.isEncrypted, rc.udpCipher)
				}
			}

			if sessVal != nil {
				if s, ok := sessVal.(*agentUDPSession); ok && s.conn != nil {
					n, err := s.conn.Write(payload)
					if err != nil {
						logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-write-local-"+routeName, fmt.Sprintf("failed to write UDP payload to local route=%s client=%s bytes=%d err=%v", routeName, clientID, len(payload), err))
						continue
					}
					if n != len(payload) {
						logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-short-write-local-"+routeName, fmt.Sprintf("short UDP payload write to local route=%s client=%s wrote=%d want=%d", routeName, clientID, n, len(payload)))
					}
				}
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
