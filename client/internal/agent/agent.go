package agent

import (
	"bytes"
	"context"
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
	"hostit/shared/version"
)

const (
	agentControlPingInterval  = 5 * time.Second
	agentControlReadDeadline  = 45 * time.Second
	agentControlWriteDeadline = 5 * time.Second
	udpRegisterInterval       = 2 * time.Second
	udpSessionIdleTimeout     = 2 * time.Minute
	// Cap concurrent public→local TCP relays (TLS dial + auth per connect).
	maxConcurrentConnects = 1024
	maxConcurrentProbes   = 4
	// versionMismatchBackoff replaces the normal reconnect backoff when the
	// server rejected our protocol version: hammering every 2s cannot
	// succeed until one side is updated.
	versionMismatchBackoff = 30 * time.Second
)

// errVersionIncompatible marks connection failures caused by protocol
// version negotiation, so the reconnect loop can back off much longer.
var errVersionIncompatible = errors.New("protocol version incompatible")

// errIdentityConflict means the server reported our Agent ID belongs to another
// agent; we regenerated a new ID and should reconnect immediately to claim it.
var errIdentityConflict = errors.New("agent id conflict")

type Hooks struct {
	OnConnected        func()
	OnEmailConfig      func(cfg emailcfg.Config)
	OnEmailProbe       func(context.Context, protocol.EmailProbeRequest) (protocol.EmailProbeResult, error)
	OnRoutes           func(routes []RemoteRoute)
	OnRouteResponse    func(apitypes.RouteResponse)
	OnRouteAck         func(apitypes.RouteAck)
	OnRouteRemoveAck   func(apitypes.RouteRemoveAck)
	OnDisconnected     func(err error)
	OnTLSPinDiscovered func(pin string)
}

type helloPayload struct {
	Routes     map[string]RemoteRoute `json:"routes"`
	Email      emailcfg.Config        `json:"email,omitempty"`
	Version    string                 `json:"version,omitempty"`
	PublicAddr string                 `json:"public_addr,omitempty"` // tunnel server hostname/IP for apps
}

func RunWithHooks(ctx context.Context, cfg Config, hooks *Hooks) error {
	a := NewAgent(cfg)
	a.hooks = hooks
	return a.Run(ctx)
}

type Agent struct {
	cfg      Config
	hooks    *Hooks
	identity *Identity

	mu                 sync.RWMutex
	controlConn        net.Conn // published only after the initial HELLO
	pendingControlConn net.Conn // dialed/handshaking; Stop must still close it
	udpDataConn        *net.UDPConn
	serverUDP          *net.UDPAddr
	udpEgress          *agentUDPEgress
	// serverPublicAddr is the tunnel server's advertised hostname/IP from HELLO
	// (ServerConfig.PublicAddr). Empty until the first HELLO of a control session.
	serverPublicAddr string

	// udpSessionID identifies this agent run; both ends derive the
	// directional UDP data keys from it, so a restart rotates them.
	udpSessionID     crypto.UDPSessionID
	udpControlNonce  crypto.UDPControlNonce
	udpRegisterReady bool
	// udpCryptoByAlg holds this run's UDP session ciphers per algorithm
	// (guarded by mu; built when HELLO announces encrypted routes).
	udpCryptoByAlg map[string]*crypto.UDPSessionCrypto
	// baseKeyByAlg caches the expensive PBKDF2 derivation per algorithm so
	// repeated HELLOs don't redo 600k hash iterations per route.
	baseKeyByAlg map[string][]byte

	controlWriteMu sync.Mutex
	routeCacheGen  atomic.Uint64
	// routeEpochs is guarded by mu. Unlike routeCacheGen, which only tells the
	// UDP receive loop to rebuild its local cache, an epoch changes only when
	// that specific route changes or is replaced. Queued egress uses it to
	// reject stale packets without penalizing unrelated routes.
	routeEpochs    map[string]uint64
	nextRouteEpoch uint64

	pendingRouteReqs  map[string]chan *apitypes.RouteResponse
	pendingRouteAcks  map[string]chan *apitypes.RouteAck
	pendingRemoveAcks map[string]chan *apitypes.RouteRemoveAck
	pendingUpdateAcks map[string]chan *apitypes.RouteUpdateAck

	connectSem chan struct{}
	probeSem   chan struct{}
	tlsSession tls.ClientSessionCache

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

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
	initialRoutes := cfg.Routes
	cfg.Routes = nil
	a := &Agent{
		cfg:               cfg,
		routeEpochs:       make(map[string]uint64, len(initialRoutes)),
		pendingRouteReqs:  make(map[string]chan *apitypes.RouteResponse),
		pendingRouteAcks:  make(map[string]chan *apitypes.RouteAck),
		pendingRemoveAcks: make(map[string]chan *apitypes.RouteRemoveAck),
		pendingUpdateAcks: make(map[string]chan *apitypes.RouteUpdateAck),
		connectSem:        make(chan struct{}, maxConcurrentConnects),
		probeSem:          make(chan struct{}, maxConcurrentProbes),
		tlsSession:        tls.NewLRUClientSessionCache(64),
	}
	a.mu.Lock()
	a.replaceRoutesLocked(initialRoutes)
	a.mu.Unlock()
	return a
}

func (a *Agent) SetHooks(hooks *Hooks) {
	a.hooks = hooks
}

// SetIdentity installs the persistent keypair/Agent ID loaded by the caller.
func (a *Agent) SetIdentity(id *Identity) {
	a.mu.Lock()
	a.identity = id
	a.mu.Unlock()
}

// ensureIdentity returns the installed identity, lazily creating an ephemeral
// one (tests / no state path) so the handshake always has a key to sign with.
func (a *Agent) ensureIdentity() (*Identity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.identity == nil {
		id, err := newEphemeralIdentity(a.cfg.EffectiveAgentID())
		if err != nil {
			return nil, err
		}
		a.identity = id
	}
	return a.identity, nil
}

// EffectiveAgentID is the agent's current authoritative ID (identity-backed,
// reflecting any server override), falling back to config.
func (a *Agent) EffectiveAgentID() string {
	a.mu.RLock()
	id := a.identity
	a.mu.RUnlock()
	if id != nil {
		return id.AgentID()
	}
	return a.cfg.EffectiveAgentID()
}

// sendAndWait sends a control packet and waits for a response (CLEAN-5).
func sendAndWait[Resp any](ctx context.Context, a *Agent,
	pending map[string]chan *Resp, key string,
	pktType byte, payload []byte, timeoutMsg string) (*Resp, error) {

	ch := make(chan *Resp, 1)
	a.mu.Lock()
	if _, exists := pending[key]; exists {
		a.mu.Unlock()
		return nil, fmt.Errorf("request %q is already in flight", key)
	}
	pending[key] = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(pending, key)
		a.mu.Unlock()
	}()

	a.controlWriteMu.Lock()
	a.mu.RLock()
	conn := a.controlConn
	a.mu.RUnlock()
	if conn == nil {
		a.controlWriteMu.Unlock()
		return nil, fmt.Errorf("not connected to server")
	}
	if err := writeControl(conn, &protocol.Packet{Type: pktType, Payload: payload}, 5*time.Second); err != nil {
		a.controlWriteMu.Unlock()
		return nil, err
	}
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

// writeControl bounds one control-channel packet write and always clears the
// deadline, including when the write fails.
func writeControl(conn net.Conn, pkt *protocol.Packet, deadline time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(deadline)); err != nil {
		return err
	}
	defer conn.SetWriteDeadline(time.Time{})
	return protocol.WritePacket(conn, pkt)
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

func tlsConfigWithPin(cfg Config) (*tls.Config, error) {
	return tlsConfigWithPinAndCache(cfg, nil)
}

func tlsConfigWithPinAndCache(cfg Config, cache tls.ClientSessionCache) (*tls.Config, error) {
	var tlsCfg *tls.Config
	if pin := strings.TrimSpace(cfg.TLSPinSHA256); pin != "" {
		expectedPin := pin
		tlsCfg = &tls.Config{
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
		}
	} else if cfg.InsecureTLS {
		logging.Global().Warnf(logging.CatEncryption, "TLS certificate verification is disabled (InsecureTLS=true). This is vulnerable to MITM attacks. Set tls_pin_sha256 for secure pinning.")
		tlsCfg = &tls.Config{InsecureSkipVerify: true}
	} else {
		return nil, fmt.Errorf("TLS is enabled but no certificate pin is configured. Set tls_pin_sha256 to the server certificate SHA-256 fingerprint, or set InsecureTLS=true to explicitly accept any certificate (not recommended)")
	}
	if cache != nil {
		tlsCfg.ClientSessionCache = cache
	}
	return tlsCfg, nil
}

func (a *Agent) Run(ctx context.Context) error {
	a.ctx, a.cancel = context.WithCancel(ctx)

	sessionID, err := crypto.NewUDPSessionID()
	if err != nil {
		return fmt.Errorf("failed to generate UDP session id: %w", err)
	}
	a.mu.Lock()
	a.udpSessionID = sessionID
	a.udpCryptoByAlg = make(map[string]*crypto.UDPSessionCrypto)
	if a.baseKeyByAlg == nil {
		a.baseKeyByAlg = make(map[string][]byte)
	}
	a.mu.Unlock()

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

		wait := backoff
		switch {
		case errors.Is(err, errVersionIncompatible):
			// Reconnecting cannot succeed until one side is updated.
			wait = versionMismatchBackoff
		case errors.Is(err, errIdentityConflict):
			// We already switched IDs; reconnect promptly to claim the new one.
			wait = 100 * time.Millisecond
			backoff = 250 * time.Millisecond
		}

		select {
		case <-a.ctx.Done():
			return nil
		case <-time.After(wait):
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
	bufferResult := netutil.SetUDPBuffers(udpConn, sharedUDPReadBufferBytes, sharedUDPWriteBufferBytes)
	if bufferResult.ReadErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request shared UDP read buffer bytes=%d: %v", bufferResult.ReadBytes, bufferResult.ReadErr)
	}
	if bufferResult.WriteErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request shared UDP write buffer bytes=%d: %v", bufferResult.WriteBytes, bufferResult.WriteErr)
	}
	egress := newAgentUDPEgress(a, udpConn, serverAddr)

	a.mu.Lock()
	a.serverUDP = serverAddr
	a.udpDataConn = udpConn
	a.udpEgress = egress
	a.mu.Unlock()

	a.sendUDPRegister()

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
				a.sendUDPRegister()
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
	a.udpEgress = nil
	a.mu.Unlock()
	if udpConn != nil {
		udpConn.Close()
	}
}

// sendUDPRegister sends a fresh identity- and control-generation-bound UDP
// registration. Before version negotiation completes there is deliberately no
// token-only fallback: protocol v3 must never publish an unbound endpoint.
func (a *Agent) sendUDPRegister() {
	a.mu.RLock()
	token := a.cfg.Token
	sessionID := a.udpSessionID
	controlNonce := a.udpControlNonce
	registerReady := a.udpRegisterReady
	id := a.identity
	egress := a.udpEgress
	a.mu.RUnlock()
	if egress == nil || id == nil || !registerReady {
		return
	}
	agentID := id.AgentID()
	authPayload, err := crypto.BuildBoundUDPRegister(token, sessionID, controlNonce, agentID, id.Sign)
	if err != nil {
		logging.Global().RateLimitedError(logging.CatUDP, "agent-udp-register-auth", fmt.Sprintf("failed to build UDP register auth: %v", err))
		return
	}
	egress.sendRegister(controlNonce, authPayload)
}

func sameUDPEgressRoute(a, b RemoteRoute) bool {
	if a.Name != b.Name || a.Proto != b.Proto || a.PublicAddr != b.PublicAddr || a.LocalAddr != b.LocalAddr || a.Encrypted != b.Encrypted {
		return false
	}
	if !a.Encrypted {
		return true
	}
	return a.Algorithm == b.Algorithm && bytes.Equal(a.DerivedKey, b.DerivedKey)
}

// nextRouteEpochLocked returns a non-zero process-local epoch. a.mu must be
// held. Epochs never need to survive a process restart.
func (a *Agent) nextRouteEpochLocked() uint64 {
	a.nextRouteEpoch++
	if a.nextRouteEpoch == 0 {
		// Reserve zero for an uninitialized route. Reaching this requires a full
		// uint64 wrap, but keeping the invariant explicit makes comparisons safe.
		a.nextRouteEpoch++
	}
	return a.nextRouteEpoch
}

// replaceRoutesLocked installs one HELLO route snapshot while preserving the
// epoch of each semantically unchanged route. a.mu must be held. A removed
// route is deliberately omitted from routeEpochs, so a later route with the
// same name receives a new epoch even when its fields match the old route.
func (a *Agent) replaceRoutesLocked(routes map[string]RemoteRoute) {
	oldRoutes := a.cfg.Routes
	oldEpochs := a.routeEpochs
	nextEpochs := make(map[string]uint64, len(routes))
	for name, route := range routes {
		if oldRoute, ok := oldRoutes[name]; ok && sameUDPEgressRoute(oldRoute, route) {
			if epoch := oldEpochs[name]; epoch != 0 {
				nextEpochs[name] = epoch
				continue
			}
		}
		nextEpochs[name] = a.nextRouteEpochLocked()
	}
	a.cfg.Routes = routes
	a.routeEpochs = nextEpochs
	a.routeCacheGen.Add(1)
}

func (a *Agent) currentUDPEgressRoute(routeName string) (RemoteRoute, *crypto.UDPSessionCrypto, uint64, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	rt, ok := a.cfg.Routes[routeName]
	epoch := a.routeEpochs[routeName]
	if !ok || epoch == 0 {
		return RemoteRoute{}, nil, 0, false
	}
	return rt, a.udpCryptoByAlg[rt.Algorithm], epoch, true
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
			tlsCfg, tlsErr = tlsConfigWithPinAndCache(a.cfg, a.tlsSession)
			if tlsErr != nil {
				return fmt.Errorf("tls config failed: %w", tlsErr)
			}
		}
		if tlsCfg != nil && a.tlsSession != nil && tlsCfg.ClientSessionCache == nil {
			tlsCfg.ClientSessionCache = a.tlsSession
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
	a.pendingControlConn = conn
	a.mu.Unlock()
	defer func() {
		conn.Close()
		a.mu.Lock()
		if a.pendingControlConn == conn {
			a.pendingControlConn = nil
		}
		if a.controlConn == conn {
			a.controlConn = nil
		}
		a.mu.Unlock()
	}()

	conn.SetDeadline(time.Now().Add(agentControlWriteDeadline))
	_, serverNonce, err := crypto.AuthenticateClient(conn, a.cfg.Token)
	if err != nil {
		return fmt.Errorf("control auth failed: %w", err)
	}
	conn.SetDeadline(time.Time{})

	id, err := a.ensureIdentity()
	if err != nil {
		return fmt.Errorf("agent identity: %w", err)
	}
	proposedID := id.AgentID()

	// Version negotiation is synchronous: send ours, then require the
	// server's reply (or its rejection reason) before anything else. We sign
	// the auth server-nonce so the server can verify we hold this ID's key.
	verPayload, _ := json.Marshal(protocol.VersionPayload{
		Version:     protocol.ProtocolVersion,
		AgentID:     proposedID,
		PublicKey:   id.PublicKey(),
		IdentitySig: id.Sign(serverNonce),
	})
	if err := writeControl(conn, &protocol.Packet{Type: protocol.TypeVersionNegotiate, Payload: verPayload}, agentControlWriteDeadline); err != nil {
		return fmt.Errorf("failed to send version negotiate: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(agentControlReadDeadline))
	var verPkt protocol.Packet
	if err := protocol.ReadPacketTo(conn, &verPkt); err != nil {
		return fmt.Errorf("failed to read version negotiate (server may predate protocol %s): %w", protocol.ProtocolVersion, err)
	}
	conn.SetReadDeadline(time.Time{})
	if verPkt.Type != protocol.TypeVersionNegotiate {
		return fmt.Errorf("expected version negotiate from server, got packet type %d", verPkt.Type)
	}
	var vp protocol.VersionPayload
	if err := json.Unmarshal(verPkt.Payload, &vp); err != nil {
		return fmt.Errorf("failed to parse version negotiate: %w", err)
	}
	if vp.Error != "" {
		return fmt.Errorf("%w: server (protocol %s) rejected connection: %s", errVersionIncompatible, vp.Version, vp.Error)
	}
	serverVer, ok := version.Parse(vp.Version)
	if !ok {
		return fmt.Errorf("server sent invalid version: %s", vp.Version)
	}
	if !protocol.IsCompatibleWith(protocol.ProtocolVersionParsed, serverVer) {
		return fmt.Errorf("%w: %s", errVersionIncompatible, protocol.IncompatibleVersionError(protocol.ProtocolVersionParsed, serverVer))
	}
	if vp.Conflict {
		newID, regenErr := id.RegenerateAgentID()
		if regenErr != nil {
			return fmt.Errorf("agent id %q conflict, regeneration failed: %w", proposedID, regenErr)
		}
		logging.Global().Warnf(logging.CatSystem, "Server reported agent id %q already in use; reconnecting as %q", proposedID, newID)
		return errIdentityConflict
	}
	if vp.AssignedAgentID != "" && vp.AssignedAgentID != proposedID {
		if setErr := id.SetAgentID(vp.AssignedAgentID); setErr != nil {
			return fmt.Errorf("failed to persist assigned agent id: %w", setErr)
		}
		logging.Global().Infof(logging.CatSystem, "Server assigned agent id %q (proposed %q)", vp.AssignedAgentID, proposedID)
	}

	controlNonce, ok := crypto.NewUDPControlNonce(serverNonce)
	if !ok {
		return fmt.Errorf("control auth returned invalid server nonce length %d", len(serverNonce))
	}
	a.mu.Lock()
	a.udpControlNonce = controlNonce
	// The server must not forward UDP until the initial HELLO has installed
	// this control generation's complete route/crypto snapshot.
	a.udpRegisterReady = false
	a.serverPublicAddr = ""
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.udpControlNonce == controlNonce {
			a.udpRegisterReady = false
			a.udpControlNonce = crypto.UDPControlNonce{}
			a.serverPublicAddr = ""
		}
		a.mu.Unlock()
	}()
	logging.Global().Infof(logging.CatSystem, "Server version negotiated: %s", serverVer)

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
				if err := writeControl(conn, &protocol.Packet{Type: protocol.TypePing}, agentControlWriteDeadline); err != nil {
					a.controlWriteMu.Unlock()
					conn.Close()
					return
				}
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
		if err := a.handleControl(connCtx, conn, tracker, controlNonce); err != nil {
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
	a.udpEgress = nil
	controlConn := a.controlConn
	pendingControlConn := a.pendingControlConn
	a.controlConn = nil
	a.pendingControlConn = nil
	if a.udpDataConn != nil {
		a.udpDataConn.Close()
		a.udpDataConn = nil
	}
	a.mu.Unlock()
	if controlConn != nil {
		controlConn.Close()
	}
	if pendingControlConn != nil && pendingControlConn != controlConn {
		pendingControlConn.Close()
	}
	a.wg.Wait()
}

// baseKeyForAlg returns the PBKDF2-derived base key for alg, caching the
// result so repeated HELLOs don't redo 600k hash iterations per route.
func (a *Agent) baseKeyForAlg(alg string) ([]byte, error) {
	a.mu.RLock()
	key, ok := a.baseKeyByAlg[alg]
	a.mu.RUnlock()
	if ok {
		return key, nil
	}
	key, err := crypto.DeriveKey(a.cfg.Token, alg)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.baseKeyByAlg == nil {
		a.baseKeyByAlg = make(map[string][]byte)
	}
	if existing, ok := a.baseKeyByAlg[alg]; ok {
		a.mu.Unlock()
		return existing, nil
	}
	a.baseKeyByAlg[alg] = key
	a.mu.Unlock()
	return key, nil
}

// ensureUDPSessionCrypto builds this run's directional UDP ciphers for alg
// if they don't exist yet. Existing ciphers are kept: the session ID is
// stable for the run, and replacing an encryptor would reset its counter.
func (a *Agent) ensureUDPSessionCrypto(alg string, baseKey []byte) error {
	a.mu.RLock()
	_, ok := a.udpCryptoByAlg[alg]
	a.mu.RUnlock()
	if ok {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.udpCryptoByAlg[alg]; ok {
		return nil
	}
	sc, err := crypto.NewUDPSessionCrypto(baseKey, a.udpSessionID[:], crypto.UDPDirClientToServer, crypto.UDPDirServerToClient)
	if err != nil {
		return err
	}
	if a.udpCryptoByAlg == nil {
		a.udpCryptoByAlg = make(map[string]*crypto.UDPSessionCrypto)
	}
	a.udpCryptoByAlg[alg] = sc
	return nil
}

func (a *Agent) EmailConfig() emailcfg.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return emailcfg.Normalize(a.cfg.Email)
}

// ServerPublicAddr returns the tunnel server's advertised hostname or IP from
// the latest HELLO (ServerConfig.PublicAddr). When the server has not configured
// one, this falls back to the host from the agent's configured Server address.
func (a *Agent) ServerPublicAddr() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if addr := strings.TrimSpace(a.serverPublicAddr); addr != "" {
		return addr
	}
	host, _ := splitHostPortOrDefault(a.cfg.Server, "7000")
	return host
}

func (a *Agent) handleControl(ctx context.Context, conn net.Conn, tracker *connTracker, controlNonce crypto.UDPControlNonce) error {
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
			if err := writeControl(conn, &protocol.Packet{
				Type:    protocol.TypePong,
				Payload: pkt.Payload,
			}, 5*time.Second); err != nil {
				logging.Global().Warnf(logging.CatTCP, "failed to write control pong: %v", err)
			}
			a.controlWriteMu.Unlock()
			continue
		}

		if pkt.Type == protocol.TypePong {
			continue
		}

		if pkt.Type == protocol.TypeVersionNegotiate {
			// Negotiation already completed synchronously in connectAndRun;
			// tolerate (and ignore) a stray re-announcement.
			continue
		}

		if pkt.Type == protocol.TypeEmailProbeRequest {
			var req protocol.EmailProbeRequest
			if err := json.Unmarshal(pkt.Payload, &req); err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to parse email probe request: %v", err)
				continue
			}
			if a.probeSem == nil {
				a.probeSem = make(chan struct{}, maxConcurrentProbes)
			}
			select {
			case a.probeSem <- struct{}{}:
			default:
				logging.Global().Warnf(logging.CatTCP, "email probe dropped: too many in flight")
				continue
			}
			go func(req protocol.EmailProbeRequest) {
				defer func() { <-a.probeSem }()
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
				select {
				case <-ctx.Done():
					return
				default:
				}
				a.controlWriteMu.Lock()
				defer a.controlWriteMu.Unlock()
				a.mu.RLock()
				live := a.controlConn
				a.mu.RUnlock()
				if live != conn {
					logging.Global().Warnf(logging.CatTCP, "skipping email probe result: control connection replaced")
					return
				}
				if err := writeControl(conn, &protocol.Packet{Type: protocol.TypeEmailProbeResult, Payload: payload}, 5*time.Second); err != nil {
					logging.Global().Errorf(logging.CatTCP, "failed to send email probe result: %v", err)
				}
			}(req)
			continue
		}

		if pkt.Type == protocol.TypeHello {
			var (
				routes     map[string]RemoteRoute
				email      emailcfg.Config
				publicAddr string
			)
			var hello helloPayload
			if err := json.Unmarshal(pkt.Payload, &hello); err == nil && hello.Routes != nil {
				routes = hello.Routes
				email = emailcfg.Normalize(hello.Email)
				publicAddr = strings.TrimSpace(hello.PublicAddr)
			} else if err := json.Unmarshal(pkt.Payload, &routes); err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to parse HELLO routes: %v", err)
				continue
			}
			for k, r := range routes {
				if r.Encrypted {
					key, err := a.baseKeyForAlg(r.Algorithm)
					if err != nil {
						logging.Global().Errorf(logging.CatTCP, "failed to derive key for route %s: %v", r.Name, err)
					} else if key != nil {
						r.DerivedKey = key
						routes[k] = r
						if err := a.ensureUDPSessionCrypto(r.Algorithm, key); err != nil {
							logging.Global().Errorf(logging.CatUDP, "failed to build UDP session crypto for route %s: %v", r.Name, err)
						}
					}
				}
			}
			a.mu.Lock()
			if a.udpControlNonce != controlNonce {
				a.mu.Unlock()
				return errors.New("control generation replaced before HELLO")
			}
			a.replaceRoutesLocked(routes)
			a.cfg.Email = email
			a.serverPublicAddr = publicAddr
			a.udpRegisterReady = true
			if a.pendingControlConn == conn {
				a.controlConn = conn
				a.pendingControlConn = nil
			}
			a.mu.Unlock()
			// The server installs the authenticated control generation before it
			// emits HELLO. Routes and crypto are now installed before the first
			// registration makes this UDP session eligible for forwarding.
			a.sendUDPRegister()
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
			pairToken := append([]byte(nil), pkt.Payload...)

			a.mu.RLock()
			rt, ok := a.cfg.Routes[routeName]
			a.mu.RUnlock()

			if !ok {
				logging.Global().Errorf(logging.CatTCP, "unknown route requested: %s", routeName)
				continue
			}

			if a.connectSem == nil {
				a.connectSem = make(chan struct{}, maxConcurrentConnects)
			}
			select {
			case a.connectSem <- struct{}{}:
			default:
				logging.Global().Warnf(logging.CatTCP, "connection limit reached, rejecting connect route=%s client=%s", routeName, clientID)
				continue
			}

			a.wg.Add(1)
			go func(ctx context.Context, routeName, clientID string, rt RemoteRoute, pairToken []byte) {
				defer a.wg.Done()
				defer func() { <-a.connectSem }()

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
					tlsCfg, tlsErr := tlsConfigWithPinAndCache(a.cfg, a.tlsSession)
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
				if len(pairToken) > 255 {
					pairToken = pairToken[:255]
				}

				buf := make([]byte, 0, 1+len(routeBytes)+1+len(clientBytes)+1+len(pairToken))
				buf = append(buf, byte(len(routeBytes)))
				buf = append(buf, routeBytes...)
				buf = append(buf, byte(len(clientBytes)))
				buf = append(buf, clientBytes...)
				buf = append(buf, byte(len(pairToken)))
				buf = append(buf, pairToken...)

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
			}(ctx, routeName, clientID, rt, pairToken)
			continue
		}

		logging.Global().RateLimitedWarn(logging.CatTCP, "agent-unknown-pkt", fmt.Sprintf("ignoring unknown control packet type=%d", pkt.Type))
	}
}

func dialLocalTCP(ctx context.Context, localAddr string) (net.Conn, error) {
	const (
		dialTimeout = 2 * time.Second
		retryDelay  = 100 * time.Millisecond
	)

	dial := func() (net.Conn, error) {
		dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 15 * time.Second}
		return dialer.DialContext(ctx, "tcp", localAddr)
	}

	conn, err := dial()
	if err == nil {
		netutil.SetTCPKeepAlive(conn, 15*time.Second)
		netutil.SetTCPNoDelay(conn)
		return conn, nil
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(retryDelay):
	}
	conn, err = dial()
	if err != nil {
		return nil, err
	}
	netutil.SetTCPKeepAlive(conn, 15*time.Second)
	netutil.SetTCPNoDelay(conn)
	return conn, nil
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
		// pin has already been established via the control connection.
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
	conn       agentUDPSessionConn
	routeEpoch uint64
}

type agentUDPSessionConn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	SetReadDeadline(time.Time) error
}

// loadAgentUDPSessionForEpoch returns only a session created for the current
// route generation. A stale session is removed before it is closed so its
// reader's deferred cleanup cannot delete a concurrently installed successor.
func loadAgentUDPSessionForEpoch(sessions *sync.Map, key any, routeEpoch uint64) (*agentUDPSession, bool) {
	for {
		value, ok := sessions.Load(key)
		if !ok {
			return nil, false
		}
		sess := value.(*agentUDPSession)
		if routeEpoch != 0 && sess.routeEpoch == routeEpoch {
			return sess, true
		}
		if sessions.CompareAndDelete(key, sess) {
			if sess.conn != nil {
				_ = sess.conn.Close()
			}
			return nil, false
		}
	}
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
	aadBuf := make([]byte, 0, 512)
	var pkt protocol.Packet

	// Only datagrams from the server's data address are honored; spoofed traffic is dropped.
	// serverUDP is set once before this loop starts and is stable for the agent's lifetime.
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
		<-ctx.Done()
		sessions.Range(func(_, v any) bool {
			_ = v.(*agentUDPSession).conn.Close()
			return true
		})
	}()

	type routeConfig struct {
		isEncrypted bool
		crypto      *crypto.UDPSessionCrypto
		localAddr   string
		epoch       uint64
	}
	routeCache := make(map[string]routeConfig)
	var lastCacheGen uint64

	rebuildRouteCache := func() {
		a.mu.RLock()
		lastCacheGen = a.routeCacheGen.Load()
		routeCache = make(map[string]routeConfig, len(a.cfg.Routes))
		for _, rt := range a.cfg.Routes {
			routeCache[rt.Name] = routeConfig{
				isEncrypted: rt.Encrypted,
				crypto:      a.udpCryptoByAlg[rt.Algorithm],
				localAddr:   rt.EffectiveLocalAddr(),
				epoch:       a.routeEpochs[rt.Name],
			}
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

			rc, ok := routeCache[routeName]
			if !ok {
				a.mu.RLock()
				rt, ok := a.cfg.Routes[routeName]
				rtCrypto := a.udpCryptoByAlg[rt.Algorithm]
				a.mu.RUnlock()
				if !ok {
					continue
				}
				rc = routeConfig{
					isEncrypted: rt.Encrypted,
					crypto:      rtCrypto,
					localAddr:   rt.EffectiveLocalAddr(),
					epoch:       a.routeEpochs[routeName],
				}
				routeCache[routeName] = rc
			}
			if rc.epoch == 0 {
				continue
			}

			payload := pkt.Payload
			if rc.isEncrypted {
				if rc.crypto == nil {
					continue
				}
				aadBuf = crypto.AppendUDPDataAAD(aadBuf[:0], routeName, clientID)
				decrypted, err := rc.crypto.Dec.Open(decryptBuf, payload, aadBuf)
				if err != nil {
					logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-open-"+routeName, fmt.Sprintf("dropping undecryptable UDP packet route=%s client=%s err=%v", routeName, clientID, err))
					continue
				}
				payload = decrypted
			}

			key := sessionKey{route: routeName, client: clientID}

			var sess *agentUDPSession
			for sess == nil {
				if current, exists := loadAgentUDPSessionForEpoch(&sessions, key, rc.epoch); exists {
					sess = current
					break
				}
				localAddr, err := net.ResolveUDPAddr("udp", rc.localAddr)
				if err != nil {
					logging.Global().Errorf(logging.CatUDP, "failed to resolve local udp addr %s: %v", rc.localAddr, err)
					break
				}

				localConn, err := net.DialUDP("udp", nil, localAddr)
				if err != nil {
					logging.Global().Errorf(logging.CatUDP, "failed to dial local udp %s: %v", rc.localAddr, err)
					break
				}
				configureLocalUDPSocket(localConn, routeName)

				newSess := &agentUDPSession{
					conn:       localConn,
					routeEpoch: rc.epoch,
				}
				actual, loaded := sessions.LoadOrStore(key, newSess)
				if loaded {
					_ = localConn.Close()
					if actual.(*agentUDPSession).routeEpoch == rc.epoch {
						sess = actual.(*agentUDPSession)
					}
					continue
				} else {
					sess = newSess

					go func(key sessionKey, sess *agentUDPSession) {
						defer func() {
							_ = sess.conn.Close()
							sessions.CompareAndDelete(key, sess)
						}()

						respBuf := make([]byte, 65536)
						// Refresh the read deadline at most once per window instead
						// of on every packet, to avoid a syscall per inbound datagram.
						const udpReadTimeout = 2 * time.Minute
						const udpReadRefresh = udpReadTimeout / 16
						deadlineSet := time.Now()
						_ = sess.conn.SetReadDeadline(deadlineSet.Add(udpReadTimeout))
						for {
							if now := time.Now(); now.Sub(deadlineSet) >= udpReadRefresh {
								_ = sess.conn.SetReadDeadline(now.Add(udpReadTimeout))
								deadlineSet = now
							}
							rn, err := sess.conn.Read(respBuf)
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

							if current, ok := sessions.Load(key); ok && current == sess {
							} else {
								return
							}

							a.mu.RLock()
							egress := a.udpEgress
							a.mu.RUnlock()
							if egress == nil {
								return
							}
							egress.sendData(key.route, key.client, sess.routeEpoch, respBuf[:rn])
						}
					}(key, newSess)
				}
			}

			if sess != nil {
				if s := sess; s.conn != nil {
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
	protocol.WarnLargeTunneledUDPDatagram(direction, routeName, clientID, frameLen, func(key, message string) {
		logging.Global().RateLimitedWarn(logging.CatUDP, key, message)
	})
}
