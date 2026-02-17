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

// payloadPool pools buffers for forwarding UDP payloads from agent to public clients.
// Eliminates per-packet make([]byte, len(payload)) allocation in the hot path.
var payloadPool = sync.Pool{New: func() any {
	b := make([]byte, 2048) // Most streaming packets fit in 1500 bytes
	return &b
}}

// logUDPBuf logs socket buffer sizes and warns if the kernel capped them.
func logUDPBuf(label string, actualRead, actualWrite, wanted int) {
	log.Infof(logging.CatUDP, "UDP buffers [%s]: read=%d write=%d (requested %d)", label, actualRead, actualWrite, wanted)
	if actualRead > 0 && actualRead < wanted/2 {
		log.Warnf(logging.CatUDP, "UDP read buffer [%s] is only %d bytes (wanted %d). "+
			"Run: sysctl -w net.core.rmem_max=%d", label, actualRead, wanted, wanted)
	}
	if actualWrite > 0 && actualWrite < wanted/2 {
		log.Warnf(logging.CatUDP, "UDP write buffer [%s] is only %d bytes (wanted %d). "+
			"Run: sysctl -w net.core.wmem_max=%d", label, actualWrite, wanted, wanted)
	}
}

// addrEqual compares two net.Addr values without string formatting.
func addrEqual(a, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	if ok1 && ok2 {
		return ua.Port == ub.Port && ua.IP.Equal(ub.IP)
	}
	// Fallback for non-UDP addresses.
	return a.String() == b.String()
}

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
	enabled := make(map[string]bool, len(cfg.Routes))
	for _, rt := range cfg.Routes {
		if rt.TCPNoDelay == nil {
			noDelay[rt.Name] = true
		} else {
			noDelay[rt.Name] = *rt.TCPNoDelay
		}
		enabled[rt.Name] = rt.IsEnabled()
	}

	st := &serverState{
		cfg:              cfg,
		pending:          map[string]pendingConn{},
		pendingByIP:      map[string]int{},
		publicUDP:        map[string]net.PacketConn{},
		dash:             newDashStateWithInterval(cfg.DashboardInterval),
		udpPublicJobs:    make(map[string]chan udpJob),
		udpPublicWriters: make(map[string]*udpWriteQueueWithBackpressure),
		errLast:          make(map[string]time.Time),
		udpStats:         udputil.NewSessionStats(1000, 5*time.Minute),
		encryptionNone:   cfg.DisableUDPEncryption || strings.EqualFold(strings.TrimSpace(cfg.UDPEncryptionMode), "none"),
		resolvedAddrs:    make(map[string]*resolvedAddr),
		noDelayByRoute:   noDelay,
		nettestPending:   make(map[string]chan nettestPong),
	}
	st.enabledByRoute.Store(enabled) // Store the map in atomic.Value for lock-free reads
	st.udpKeys = buildUDPKeySet(cfg)
	return &Server{cfg: cfg, st: st}
}

func buildUDPKeySet(cfg ServerConfig) udputil.KeySet {
	mode := udputil.NormalizeMode(cfg.UDPEncryptionMode)
	if cfg.DisableUDPEncryption {
		mode = udputil.ModeNone
	}
	if mode == udputil.ModeNone {
		ks, _ := udputil.NewKeySet(mode, "", 0, nil, 0, nil)
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
	ks, err := udputil.NewKeySet(mode, strings.TrimSpace(cfg.Token), cfg.UDPKeyID, curSalt, cfg.UDPPrevKeyID, prevSalt)
	if err != nil {
		ks, _ = udputil.NewKeySet(udputil.ModeNone, "", 0, nil, 0, nil)
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
		publicDepth := 0
		publicCap := 0
		for _, q := range s.st.udpPublicWriters {
			if q == nil {
				continue
			}
			d, c, _, _, _, _, _ := q.Stats()
			publicDepth += d
			publicCap += c
		}
		agentDepth := 0
		agentCap := 0
		if s.st.udpAgentWriteQueue != nil {
			agentDepth, agentCap, _, _, _, _, _ = s.st.udpAgentWriteQueue.Stats()
		}

		publicQueueDrops := uint64(s.st.udpPublicWriteDrops.Load())
		agentQueueDrops := uint64(s.st.udpAgentWriteDrops.Load())
		publicWorkerDrops := uint64(maxI64(s.st.udpPublicDrops.Load(), 0))
		agentWorkerDrops := uint64(maxI64(s.st.udpAgentDrops.Load(), 0))
		resolveDrops := s.st.udpResolveDrops.Load()
		decodeDrops := s.st.udpDecodeDrops.Load()
		noAgentDrops := s.st.udpNoAgentDrops.Load()
		routeDisabledDrops := s.st.udpRouteDisabledDrops.Load()
		payloadTooLargeDrops := s.st.udpPayloadTooLargeDrops.Load()
		publicWriteErrors := s.st.udpPublicWriteErrors.Load()
		agentWriteErrors := s.st.udpAgentWriteErrors.Load()

		totalDrops := publicQueueDrops + agentQueueDrops + publicWorkerDrops + agentWorkerDrops +
			resolveDrops + decodeDrops + noAgentDrops + routeDisabledDrops + payloadTooLargeDrops +
			publicWriteErrors + agentWriteErrors

		delivered := s.st.udpPacketsOut.Load()
		attempted := delivered + totalDrops
		lossPct := 0.0
		if attempted > 0 {
			lossPct = (float64(totalDrops) / float64(attempted)) * 100.0
		}

		snap.UDP = &UDPStats{
			PacketsIn:            int64(s.st.udpPacketsIn.Load()),
			PacketsOut:           int64(s.st.udpPacketsOut.Load()),
			BytesIn:              int64(s.st.udpBytesIn.Load()),
			BytesOut:             int64(s.st.udpBytesOut.Load()),
			ActiveRoutes:         len(summary.ByRoute),
			LossPercent:          lossPct,
			TotalDrops:           int64(totalDrops),
			PublicQueueDrops:     int64(publicQueueDrops),
			AgentQueueDrops:      int64(agentQueueDrops),
			PublicWorkerDrops:    int64(publicWorkerDrops),
			AgentWorkerDrops:     int64(agentWorkerDrops),
			ResolveDrops:         int64(resolveDrops),
			DecodeDrops:          int64(decodeDrops),
			NoAgentDrops:         int64(noAgentDrops),
			RouteDisabledDrops:   int64(routeDisabledDrops),
			PayloadTooLargeDrops: int64(payloadTooLargeDrops),
			PublicWriteErrors:    int64(publicWriteErrors),
			AgentWriteErrors:     int64(agentWriteErrors),
			PublicQueueDepth:     int64(publicDepth),
			PublicQueueCapacity:  int64(publicCap),
			AgentQueueDepth:      int64(agentDepth),
			AgentQueueCapacity:   int64(agentCap),
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

	// Use larger buffer sizes for high-throughput scenarios.
	// 64MB gives more burst absorption for high-FPS game streaming.
	wantBuf := 64 * 1024 * 1024
	if s.cfg.UDPBufferSize != nil && *s.cfg.UDPBufferSize > 0 {
		wantBuf = *s.cfg.UDPBufferSize
	}

	udpDataConn, err := net.ListenPacket("udp", s.cfg.DataAddr)
	if err != nil {
		return fmt.Errorf("listen data udp: %w", err)
	}
	if uc, ok := udpDataConn.(*net.UDPConn); ok {
		ar, aw := trySetUDPBuffers(uc, wantBuf)
		logUDPBuf("data", ar, aw, wantBuf)
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
			ar, aw := trySetUDPBuffers(uc, wantBuf)
			logUDPBuf("public/"+rt.Name, ar, aw, wantBuf)
		}
		publicUDP = append(publicUDP, publicUDPListener{name: rt.Name, pc: pc})
	}
	defer func() {
		for _, x := range publicUDP {
			_ = x.pc.Close()
		}
	}()

	st := s.st
	log.Info(logging.CatUDP, "UDP profile: fast (low-latency, drop-on-overload)")
	udpWriteWorkers := runtime.NumCPU()
	if udpWriteWorkers < 2 {
		udpWriteWorkers = 2
	}
	if udpWriteWorkers > 16 {
		udpWriteWorkers = 16
	}
	if nStr := os.Getenv("HOSTIT_UDP_WRITE_WORKERS"); nStr != "" {
		if n, err := strconv.Atoi(nStr); err == nil && n >= 1 && n <= 32 {
			udpWriteWorkers = n
		}
	}
	udpWriteQueueSize := 131072
	if s.cfg.UDPQueueSize != nil && *s.cfg.UDPQueueSize > 0 {
		udpWriteQueueSize = *s.cfg.UDPQueueSize
	}
	maxQueueLatencyMs := envIntBound("HOSTIT_UDP_MAX_QUEUE_LATENCY_MS", 0, 0, 5000)
	highWaterPct := envIntBound("HOSTIT_UDP_HIGH_WATER_PCT", 90, 50, 98)
	st.udpQueueBaseBudget = time.Duration(maxQueueLatencyMs) * time.Millisecond
	st.udpQueueTightBudget = st.udpQueueBaseBudget / 2
	if st.udpQueueBaseBudget > 0 && st.udpQueueTightBudget < 5*time.Millisecond {
		st.udpQueueTightBudget = 5 * time.Millisecond
	}
	st.udpQueueHighWater = highWaterPct
	st.udpEnqueueWait = time.Duration(envIntBound("HOSTIT_UDP_ENQUEUE_WAIT_US", 5000, 0, 50000)) * time.Microsecond
	maxPayloadDefault := 1400
	if s.cfg.UDPMaxPayload != nil {
		maxPayloadDefault = *s.cfg.UDPMaxPayload
	}
	st.udpMaxPayload = envIntBound("HOSTIT_UDP_MAX_PAYLOAD", maxPayloadDefault, 0, 65507)
	st.udpDirectRelay = true
	if v := strings.TrimSpace(os.Getenv("HOSTIT_UDP_DIRECT_RELAY")); v != "" {
		lv := strings.ToLower(v)
		if lv == "0" || lv == "false" || lv == "no" || lv == "off" {
			st.udpDirectRelay = false
		}
	}
	if st.udpMaxPayload > 0 {
		log.Infof(logging.CatUDP, "UDP max payload cap enabled: %d bytes", st.udpMaxPayload)
	} else {
		log.Warn(logging.CatUDP, "UDP max payload cap disabled; large packets may fragment and drop on internet paths")
	}
	if st.udpDirectRelay {
		log.Info(logging.CatUDP, "UDP relay mode: direct (immediate receive->send, minimal queueing)")
	} else {
		log.Info(logging.CatUDP, "UDP relay mode: queued (async writers + burst absorption)")
	}
	st.udpData = udpDataConn
	for _, x := range publicUDP {
		st.publicUDP[x.name] = x.pc
	}

	if !st.udpDirectRelay {
		// Start async UDP writers for each public route (server→public client path)
		// This prevents blocking on slow clients and absorbs traffic bursts
		for _, x := range publicUDP {
			writeQueue := newUDPWriteQueueWithBackpressure(udpWriteQueueSize)
			st.udpPublicWriters[x.name] = writeQueue

			for i := 0; i < udpWriteWorkers; i++ {
				go st.udpPublicWriter(ctx, x.pc, writeQueue, x.name)
			}
		}

		// Start async UDP writer for server→agent path (prevents blocking workers on slow agent)
		// This is critical for high-FPS streaming - blocking writes cause worker starvation
		st.udpAgentWriteQueue = newUDPWriteQueueWithBackpressure(udpWriteQueueSize)
		for i := 0; i < udpWriteWorkers; i++ {
			go st.udpAgentWriter(ctx, udpDataConn)
		}
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
	udpKeys udputil.KeySet
	dash    *dashState

	errMu   sync.Mutex
	errLast map[string]time.Time

	mu           sync.Mutex
	agentConn    net.Conn
	agentProto   *lineproto.RW
	agentWriteMu sync.Mutex
	agentCancel  context.CancelFunc // cancels all active pipes tied to the current agent
	agentCtx     context.Context    // derived context for the current agent session
	udpData      net.PacketConn
	publicUDP    map[string]net.PacketConn

	// Lock-free agent UDP state (hot path — read on every packet)
	agentUDPAddr  atomic.Value // stores net.Addr (nil = not registered)
	agentUDPKeyID atomic.Uint32

	// Cached encryption mode (computed once at creation, avoids per-packet string ops)
	encryptionNone bool

	// Precomputed route properties (avoids linear scan per connection).
	noDelayByRoute map[string]bool
	// enabledByRoute stores route enabled state as map[string]bool in an atomic.Value
	// for lock-free reads on the hot path (every incoming UDP packet).
	enabledByRoute atomic.Value

	pendingMu   sync.Mutex
	pending     map[string]pendingConn
	pendingByIP map[string]int // track pending count per IP for DoS prevention

	// Parallelization structures
	udpAgentJobs  chan udpJob
	udpPublicJobs map[string]chan udpJob

	// Async write queues for server→public client path (prevents blocking on slow clients)
	udpPublicWriters    map[string]*udpWriteQueueWithBackpressure // route -> write queue
	udpPublicWriteDrops atomic.Int64

	// Async write queue for server→agent path (prevents blocking workers on slow agent connections)
	udpAgentWriteQueue *udpWriteQueueWithBackpressure
	udpAgentWriteDrops atomic.Int64

	// UDP statistics
	udpStats      *udputil.SessionStats
	udpPacketsIn  atomic.Uint64
	udpPacketsOut atomic.Uint64
	udpBytesIn    atomic.Uint64
	udpBytesOut   atomic.Uint64

	udpQueueBaseBudget  time.Duration
	udpQueueTightBudget time.Duration
	udpQueueHighWater   int
	udpEnqueueWait      time.Duration
	udpMaxPayload       int
	udpDirectRelay      bool

	// UDP drop counters (atomic, for diagnostics)
	udpAgentDrops           atomic.Int64
	udpPublicDrops          atomic.Int64
	udpResolveDrops         atomic.Uint64
	udpDecodeDrops          atomic.Uint64
	udpNoAgentDrops         atomic.Uint64
	udpRouteDisabledDrops   atomic.Uint64
	udpPayloadTooLargeDrops atomic.Uint64
	udpPublicWriteErrors    atomic.Uint64
	udpAgentWriteErrors     atomic.Uint64

	// Monotonic sequence for server->agent UDP encapsulation.
	udpSeqToAgent atomic.Uint32

	// Network test control-channel state.
	nettestRunMu   sync.Mutex
	nettestMu      sync.Mutex
	nettestPending map[string]chan nettestPong

	// Resolved-address cache for outbound UDP replies (avoids net.ResolveUDPAddr per packet).
	resolvedMu     sync.RWMutex
	resolvedAddrs  map[string]*resolvedAddr
	resolvingAddrs map[string]chan struct{} // Tracks in-progress resolutions to avoid duplicates
}

// resolvedAddr caches a resolved UDP address with its creation time for eviction.
type resolvedAddr struct {
	addr    *net.UDPAddr
	created time.Time
}

// udpWriteJob represents a packet to write to a public client
type udpWriteJob struct {
	data    []byte
	addr    net.Addr
	bufPtr  *[]byte   // Pool buffer to return after writing (nil if data was copied)
	enqueue time.Time // When the job was enqueued (for latency tracking)
}

// udpWriteQueueWithBackpressure is a write queue with backpressure support.
type udpWriteQueueWithBackpressure struct {
	queue       chan udpWriteJob
	capacity    int
	depth       atomic.Int32
	drops       atomic.Uint64
	avgLatency  atomic.Int64 // Average queue latency in nanoseconds
	totalBytes  atomic.Uint64
	totalWrites atomic.Uint64

	// Congestion control
	congestionMode    atomic.Bool
	lastDropTime      atomic.Int64
	congestionBackoff atomic.Int64 // nanoseconds to wait between sends
}

func newUDPWriteQueueWithBackpressure(capacity int) *udpWriteQueueWithBackpressure {
	return &udpWriteQueueWithBackpressure{
		queue:    make(chan udpWriteJob, capacity),
		capacity: capacity,
	}
}

// TryEnqueue attempts to enqueue without blocking. Returns false if dropped.
func (q *udpWriteQueueWithBackpressure) TryEnqueue(data []byte, addr net.Addr, bufPtr *[]byte) bool {
	job := udpWriteJob{
		data:    data,
		addr:    addr,
		bufPtr:  bufPtr,
		enqueue: time.Now(),
	}
	select {
	case q.queue <- job:
		q.depth.Add(1)
		return true
	default:
		q.drops.Add(1)
		q.enterCongestionMode()
		// NOTE: Do NOT return bufPtr to a pool here — the caller owns the
		// buffer and must choose the correct pool (payloadPool, outPool, etc.).
		// Returning to the wrong pool causes buffer-size corruption.
		return false
	}
}

// EnqueueWithTimeout attempts to enqueue and waits up to timeout when the queue is full.
// Returns false if still full after waiting.
func (q *udpWriteQueueWithBackpressure) EnqueueWithTimeout(data []byte, addr net.Addr, bufPtr *[]byte, timeout time.Duration) bool {
	if timeout <= 0 {
		return q.TryEnqueue(data, addr, bufPtr)
	}
	job := udpWriteJob{
		data:    data,
		addr:    addr,
		bufPtr:  bufPtr,
		enqueue: time.Now(),
	}
	select {
	case q.queue <- job:
		q.depth.Add(1)
		return true
	default:
	}

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case q.queue <- job:
		q.depth.Add(1)
		return true
	case <-t.C:
		q.drops.Add(1)
		q.enterCongestionMode()
		return false
	}
}

// Dequeue returns the next job to process.
func (q *udpWriteQueueWithBackpressure) Dequeue(ctx context.Context) (udpWriteJob, bool) {
	select {
	case job, ok := <-q.queue:
		if !ok {
			return udpWriteJob{}, false
		}
		q.depth.Add(-1)
		// Track latency
		if !job.enqueue.IsZero() {
			latency := time.Since(job.enqueue).Nanoseconds()
			oldAvg := q.avgLatency.Load()
			if oldAvg == 0 {
				q.avgLatency.Store(latency)
			} else {
				newAvg := oldAvg - oldAvg/10 + latency/10
				q.avgLatency.Store(newAvg)
			}
		}
		return job, true
	case <-ctx.Done():
		return udpWriteJob{}, false
	}
}

func (q *udpWriteQueueWithBackpressure) enterCongestionMode() {
	q.lastDropTime.Store(time.Now().UnixNano())
	if !q.congestionMode.Swap(true) {
		q.congestionBackoff.Store(100 * 1000) // 100 microseconds
		log.Warn(logging.CatUDP, "UDP write queue entering congestion mode")
	}
}

func (q *udpWriteQueueWithBackpressure) maybeExitCongestionMode() {
	if !q.congestionMode.Load() {
		return
	}
	lastDrop := q.lastDropTime.Load()
	if time.Since(time.Unix(0, lastDrop)) > 5*time.Second {
		q.congestionMode.Store(false)
		q.congestionBackoff.Store(0)
		log.Info(logging.CatUDP, "UDP write queue exited congestion mode")
		return
	}
	// Gradually reduce backoff
	currentBackoff := q.congestionBackoff.Load()
	if currentBackoff > 1000 {
		newBackoff := currentBackoff - currentBackoff/10
		q.congestionBackoff.Store(newBackoff)
	}
}

// Stats returns queue statistics.
func (q *udpWriteQueueWithBackpressure) Stats() (depth, capacity int, drops, totalBytes, totalWrites uint64, avgLatency time.Duration, inCongestion bool) {
	return int(q.depth.Load()), q.capacity, q.drops.Load(), q.totalBytes.Load(), q.totalWrites.Load(),
		time.Duration(q.avgLatency.Load()), q.congestionMode.Load()
}

const dashSystemRoute = "_system"

type udpJob struct {
	data   []byte
	len    int // Actual data length (data may be from pool with larger capacity)
	addr   net.Addr
	bufPtr *[]byte    // Pool buffer to return after processing (nil if data was copied)
	pool   *sync.Pool // Pool to return buffer to (must match the pool it came from)
	enq    time.Time
}

func envIntBound(name string, def, min, max int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func adaptiveBudget(base, tight time.Duration, depth, capacity, highWaterPct int) time.Duration {
	if capacity <= 0 {
		return base
	}
	if depth*100 >= capacity*highWaterPct {
		return tight
	}
	return base
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

// getAgentCtx returns the context for the current agent session.
// When the agent disconnects, this context is cancelled, which terminates
// all active pipe connections tied to it.
func (st *serverState) getAgentCtx() context.Context {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.agentCtx != nil {
		return st.agentCtx
	}
	// No agent connected — return an already-cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
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

// routeEnabled returns true if the route is enabled (can be toggled at runtime).
// Uses atomic.Value for lock-free reads on the hot path (every incoming UDP packet).
func (st *serverState) routeEnabled(routeName string) bool {
	v := st.enabledByRoute.Load()
	if v == nil {
		return true // default
	}
	enabledMap, ok := v.(map[string]bool)
	if !ok {
		return true // default
	}
	if enabled, exists := enabledMap[routeName]; exists {
		return enabled
	}
	return true // default
}

// SetRouteEnabled toggles a route's enabled state at runtime.
// Returns the new enabled state, or false if the route doesn't exist.
// Uses copy-on-write pattern to update the map atomically.
func (s *Server) SetRouteEnabled(routeName string, enabled bool) bool {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()

	// Check if route exists
	found := false
	for _, rt := range s.st.cfg.Routes {
		if rt.Name == routeName {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	// Update the enabled state using copy-on-write pattern
	oldMap := s.st.enabledByRoute.Load()
	if oldMap != nil {
		oldEnabledMap, ok := oldMap.(map[string]bool)
		if ok {
			// Create a new map with the updated value
			newMap := make(map[string]bool, len(oldEnabledMap)+1)
			for k, v := range oldEnabledMap {
				newMap[k] = v
			}
			newMap[routeName] = enabled
			s.st.enabledByRoute.Store(newMap)
		}
	}

	// Update the config as well for persistence
	for i := range s.st.cfg.Routes {
		if s.st.cfg.Routes[i].Name == routeName {
			s.st.cfg.Routes[i].Enabled = &enabled
			break
		}
	}

	log.Infof(logging.CatControl, "route %s %s", routeName, map[bool]string{true: "enabled", false: "disabled"}[enabled])
	return true
}

// GetRouteEnabled returns the current enabled state of a route.
func (s *Server) GetRouteEnabled(routeName string) bool {
	return s.st.routeEnabled(routeName)
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
		// Cancel all active pipes from the previous agent session.
		if st.agentCancel != nil {
			st.agentCancel()
			st.agentCancel = nil
			st.agentCtx = nil
		}
		st.setAgentUDPAddr(nil)
		st.agentUDPKeyID.Store(0)
	}
	st.mu.Unlock()
	if prevConn != nil {
		st.drainAllPending()
	}

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

	// NOW mark the agent as connected - after READY is sent and agent is listening.
	// Create a per-agent context so all active pipes tied to this agent can be
	// cancelled instantly when the agent disconnects.
	agentCtx, agentCancel := context.WithCancel(ctx)
	st.mu.Lock()
	st.agentConn = conn
	st.agentProto = rw
	st.agentCtx = agentCtx
	st.agentCancel = agentCancel
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
	// Use configured values or defaults.
	pingEvery := 5 * time.Second
	if st.cfg.AgentHeartbeatInterval > 0 {
		pingEvery = st.cfg.AgentHeartbeatInterval
	}
	deadAfter := 10 * time.Second
	if st.cfg.AgentHeartbeatTimeout > 0 {
		deadAfter = st.cfg.AgentHeartbeatTimeout
	}
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
			case "NETTEST_PONG":
				st.handleNettestPong(rest)
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
	// Capture the connection to close outside the lock to avoid potential deadlock
	// if Close() blocks on I/O operations.
	connToClose := st.agentConn
	st.agentConn = nil
	st.agentProto = nil
	// Cancel the agent context — this immediately terminates all active
	// bidirPipe goroutines that are proxying traffic for this agent.
	if st.agentCancel != nil {
		st.agentCancel()
		st.agentCancel = nil
		st.agentCtx = nil
	}
	st.setAgentUDPAddr(nil)
	st.agentUDPKeyID.Store(0)
	st.mu.Unlock()
	st.clearNettestPending()

	// Close the connection outside the mutex lock to prevent deadlock.
	if connToClose != nil {
		_ = connToClose.Close()
	}

	log.Info(logging.CatControl, "agent cleared, draining pending connections")

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

	// Check if route is enabled
	if !st.routeEnabled(routeName) {
		log.Debug(logging.CatPairing, "public connection rejected: route disabled", logging.F(
			"route", routeName,
			"remote_ip", remoteIP,
			"conn_id", id,
		))
		if st.dash != nil {
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: time.Now().Unix(), Kind: "reject_route_disabled", RemoteIP: remoteIP, ConnID: id})
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
		// Use the agent-scoped context: if the agent disconnects, all active
		// pipes are terminated immediately instead of hanging until TCP timeout.
		agentCtx := st.getAgentCtx()
		a2b, b2a := bidirPipeCount(agentCtx, clientConn, agentConn)
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

	// Determine worker count from config, environment, or defaults
	workers := runtime.NumCPU() * 4 // Increased from 2x to 4x for high-load
	if workers < 16 {
		workers = 16 // Increased minimum
	}
	if workers > 256 {
		workers = 256 // Increased max
	}
	if st.cfg.UDPWorkerCount != nil && *st.cfg.UDPWorkerCount > 0 {
		workers = *st.cfg.UDPWorkerCount
	} else if numWorkers := os.Getenv("HOSTIT_UDP_WORKERS"); numWorkers != "" {
		if n, err := strconv.Atoi(numWorkers); err == nil && n > 0 && n <= 256 {
			workers = n
		}
	}

	// Large buffer to absorb bursts without dropping packets.
	jobBufSize := 131072
	if st.cfg.UDPQueueSize != nil && *st.cfg.UDPQueueSize > 0 {
		jobBufSize = *st.cfg.UDPQueueSize
	}
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
		var prevWriteDrops int64
		var prevAgentWriteDrops int64
		var prevPublicWriteErrors uint64
		var prevAgentWriteErrors uint64
		var prevResolveDrops uint64
		var prevDecodeDrops uint64
		var prevNoAgentDrops uint64
		var prevRouteDisabledDrops uint64
		var prevPayloadTooLargeDrops uint64
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

				wd := st.udpPublicWriteDrops.Load()
				if wd > prevWriteDrops {
					log.Warnf(logging.CatUDP, "UDP public write queue drops: %d total (%d new)", wd, wd-prevWriteDrops)
				}
				prevWriteDrops = wd

				awd := st.udpAgentWriteDrops.Load()
				if awd > prevAgentWriteDrops {
					log.Warnf(logging.CatUDP, "UDP agent write queue drops: %d total (%d new)", awd, awd-prevAgentWriteDrops)
				}
				prevAgentWriteDrops = awd

				pwe := st.udpPublicWriteErrors.Load()
				if pwe > prevPublicWriteErrors {
					log.Warnf(logging.CatUDP, "UDP public write errors: %d total (%d new)", pwe, pwe-prevPublicWriteErrors)
				}
				prevPublicWriteErrors = pwe

				awe := st.udpAgentWriteErrors.Load()
				if awe > prevAgentWriteErrors {
					log.Warnf(logging.CatUDP, "UDP agent write errors: %d total (%d new)", awe, awe-prevAgentWriteErrors)
				}
				prevAgentWriteErrors = awe

				rd := st.udpResolveDrops.Load()
				if rd > prevResolveDrops {
					log.Warnf(logging.CatUDP, "UDP resolve drops: %d total (%d new)", rd, rd-prevResolveDrops)
				}
				prevResolveDrops = rd

				dd := st.udpDecodeDrops.Load()
				if dd > prevDecodeDrops {
					log.Warnf(logging.CatUDP, "UDP decode drops: %d total (%d new)", dd, dd-prevDecodeDrops)
				}
				prevDecodeDrops = dd

				nad := st.udpNoAgentDrops.Load()
				if nad > prevNoAgentDrops {
					log.Warnf(logging.CatUDP, "UDP no-agent drops: %d total (%d new)", nad, nad-prevNoAgentDrops)
				}
				prevNoAgentDrops = nad

				rdd := st.udpRouteDisabledDrops.Load()
				if rdd > prevRouteDisabledDrops {
					log.Warnf(logging.CatUDP, "UDP route-disabled drops: %d total (%d new)", rdd, rdd-prevRouteDisabledDrops)
				}
				prevRouteDisabledDrops = rdd

				ptld := st.udpPayloadTooLargeDrops.Load()
				if ptld > prevPayloadTooLargeDrops {
					log.Warnf(logging.CatUDP, "UDP payload-too-large drops: %d total (%d new)", ptld, ptld-prevPayloadTooLargeDrops)
				}
				prevPayloadTooLargeDrops = ptld
			}
		}
	}()

	// Multiple readers to avoid single-reader bottleneck
	// Increased reader count for better parallelism
	numReaders := runtime.NumCPU()
	if numReaders < 4 {
		numReaders = 4
	}
	if numReaders > 32 {
		numReaders = 32 // Increased cap
	}
	if st.cfg.UDPReaderCount != nil && *st.cfg.UDPReaderCount > 0 {
		numReaders = *st.cfg.UDPReaderCount
	}

	readerDone := make(chan struct{})
	var readerWg sync.WaitGroup
	enqueueWait := time.Duration(envIntBound("HOSTIT_UDP_ENQUEUE_WAIT_US", 5000, 0, 50000)) * time.Microsecond

	for i := 0; i < numReaders; i++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			// Per-reader buffer pool to avoid contention
			localPool := &sync.Pool{
				New: func() any {
					b := make([]byte, 64*1024)
					return &b
				},
			}

			for {
				select {
				case <-readerDone:
					return
				default:
				}

				bufPtr := localPool.Get().(*[]byte)
				buf := *bufPtr
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					localPool.Put(bufPtr)
					if ctx.Err() != nil {
						return
					}
					if errors.Is(err, net.ErrClosed) {
						return
					}
					if ne, ok := err.(net.Error); ok && (ne.Temporary() || ne.Timeout()) {
						continue
					}
					st.dashError(dashSystemRoute, "error_accept_agent_udp", hostFromAddr(addr), "", err.Error())
					return
				}

				job := udpJob{data: buf, len: n, addr: addr, bufPtr: bufPtr, pool: localPool, enq: time.Now()}
				enqueued := false
				select {
				case jobs <- job:
					enqueued = true
				default:
					if enqueueWait > 0 {
						t := time.NewTimer(enqueueWait)
						select {
						case jobs <- job:
							enqueued = true
						case <-t.C:
						}
						t.Stop()
					}
				}
				if !enqueued {
					st.udpAgentDrops.Add(1)
					st.dashErrorRateLimited(dashSystemRoute, "loss_udp_agent_reader_overload", hostFromAddr(addr), "", "agent UDP reader dropped packet (worker queue full)", 1*time.Second)
					localPool.Put(bufPtr)
				}
			}
		}()
	}

	// Wait for context cancellation
	<-ctx.Done()
	close(readerDone)
	readerWg.Wait()
	close(jobs)
	return nil
}

// resolveUDP caches resolved UDP addresses to avoid net.ResolveUDPAddr per packet.
// Entries older than 5 minutes are evicted to prevent unbounded memory growth.
const resolvedAddrTTL = 5 * time.Minute

// resolveUDP returns a cached UDP address or resolves synchronously on cache miss.
// Unlike the previous async/drop behavior, this avoids dropping first packets for
// unseen addresses; only true resolution failures return nil.
func (st *serverState) resolveUDP(addr string) *net.UDPAddr {
	st.resolvedMu.RLock()
	cached, ok := st.resolvedAddrs[addr]
	var wait chan struct{}
	if st.resolvingAddrs != nil {
		wait = st.resolvingAddrs[addr]
	}
	st.resolvedMu.RUnlock()
	if ok && time.Since(cached.created) < resolvedAddrTTL {
		return cached.addr
	}

	if wait != nil {
		t := time.NewTimer(3 * time.Millisecond)
		select {
		case <-wait:
		case <-t.C:
		}
		t.Stop()
		st.resolvedMu.RLock()
		if cached2, ok2 := st.resolvedAddrs[addr]; ok2 && time.Since(cached2.created) < resolvedAddrTTL {
			st.resolvedMu.RUnlock()
			return cached2.addr
		}
		st.resolvedMu.RUnlock()
	}

	st.resolvedMu.Lock()
	if cached2, ok2 := st.resolvedAddrs[addr]; ok2 && time.Since(cached2.created) < resolvedAddrTTL {
		st.resolvedMu.Unlock()
		return cached2.addr
	}
	if st.resolvingAddrs == nil {
		st.resolvingAddrs = make(map[string]chan struct{})
	}
	if wait2, exists := st.resolvingAddrs[addr]; exists {
		st.resolvedMu.Unlock()
		t := time.NewTimer(5 * time.Millisecond)
		select {
		case <-wait2:
		case <-t.C:
		}
		t.Stop()
		st.resolvedMu.RLock()
		if cached3, ok3 := st.resolvedAddrs[addr]; ok3 && time.Since(cached3.created) < resolvedAddrTTL {
			st.resolvedMu.RUnlock()
			return cached3.addr
		}
		st.resolvedMu.RUnlock()
		ua, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			traceUDPf("udp: resolve failed addr=%s err=%v", addr, err)
			return nil
		}
		return ua
	}
	done := make(chan struct{})
	st.resolvingAddrs[addr] = done
	st.resolvedMu.Unlock()

	ua, err := net.ResolveUDPAddr("udp", addr)

	st.resolvedMu.Lock()
	defer st.resolvedMu.Unlock()
	delete(st.resolvingAddrs, addr)
	close(done)
	if err != nil {
		traceUDPf("udp: resolve failed addr=%s err=%v", addr, err)
		return nil
	}

	now := time.Now()
	for k, v := range st.resolvedAddrs {
		if now.Sub(v.created) > resolvedAddrTTL {
			delete(st.resolvedAddrs, k)
		}
	}
	if len(st.resolvedAddrs) < 100000 {
		st.resolvedAddrs[addr] = &resolvedAddr{addr: ua, created: now}
	}
	return ua
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
			budget := adaptiveBudget(st.udpQueueBaseBudget, st.udpQueueTightBudget, len(jobs), cap(jobs), st.udpQueueHighWater)
			if budget > 0 && !job.enq.IsZero() && time.Since(job.enq) > budget {
				st.udpAgentDrops.Add(1)
				st.dashErrorRateLimited(dashSystemRoute, "loss_udp_agent_worker_stale", hostFromAddr(job.addr), "", "agent UDP worker dropped stale packet", 1*time.Second)
				if job.bufPtr != nil && job.pool != nil {
					job.pool.Put(job.bufPtr)
				}
				continue
			}
			pkt := job.data
			if job.len > 0 && job.len < len(pkt) {
				pkt = pkt[:job.len]
			}
			st.processAgentUDPPacket(pkt, job.addr)
			// Return buffer to the correct pool after processing
			if job.bufPtr != nil && job.pool != nil {
				job.pool.Put(job.bufPtr)
			}
		}
	}
}

func (st *serverState) processAgentUDPPacket(pkt []byte, addr net.Addr) {
	if len(pkt) == 0 {
		return
	}
	enqueueWait := st.udpEnqueueWait
	encNone := st.encryptionNone
	switch pkt[0] {
	case udputil.MsgReg:
		if !encNone {
			return
		}
		tok, ok := udputil.DecodeReg(pkt)
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
		if oldAddr == nil || !addrEqual(oldAddr, addr) {
			log.Infof(logging.CatUDP, "agent UDP registered addr=%v mode=plaintext", addr)
		}
	case udputil.MsgRegEnc2:
		if encNone {
			return
		}
		expected := strings.TrimSpace(st.cfg.Token)
		if expected == "" {
			return
		}
		kid, ok := udputil.DecodeRegEnc2(st.udpKeys, expected, pkt)
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
		if oldAddr == nil || !addrEqual(oldAddr, addr) {
			log.Infof(logging.CatUDP, "agent UDP registered addr=%v mode=encrypted keyID=%d", addr, kid)
		}
	case udputil.MsgData:
		if !encNone {
			return
		}
		route, client, payload, ok := udputil.DecodeData(pkt)
		if !ok {
			st.udpDecodeDrops.Add(1)
			traceUDPf("udp: DATA decode failed from=%v", addr)
			st.dashErrorRateLimited(dashSystemRoute, "error_udp_data_decode", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		st.udpPacketsIn.Add(1)
		st.udpBytesIn.Add(uint64(len(payload)))
		agent := st.getAgentUDPAddr()
		if agent == nil || !addrEqual(agent, addr) {
			return
		}
		st.forwardAgentPayloadToPublic(route, client, payload, addr, enqueueWait, "DATA")
	case udputil.MsgDataSeq:
		if !encNone {
			return
		}
		_, route, client, payload, ok := udputil.DecodeDataWithSeq(pkt)
		if !ok {
			st.udpDecodeDrops.Add(1)
			traceUDPf("udp: DATASeq decode failed from=%v", addr)
			st.dashErrorRateLimited(dashSystemRoute, "error_udp_dataseq_decode", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		st.udpPacketsIn.Add(1)
		st.udpBytesIn.Add(uint64(len(payload)))
		agent := st.getAgentUDPAddr()
		if agent == nil || !addrEqual(agent, addr) {
			return
		}
		st.forwardAgentPayloadToPublic(route, client, payload, addr, enqueueWait, "DATASeq")
	case udputil.MsgDataEnc2:
		if encNone {
			return
		}
		route, client, payload, _, ok := udputil.DecodeDataEnc2(st.udpKeys, pkt)
		if !ok {
			st.udpDecodeDrops.Add(1)
			traceUDPf("udp: DATAEnc2 decode failed from=%v", addr)
			st.dashErrorRateLimited(dashSystemRoute, "error_udp_dataenc2_decode", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		st.udpPacketsIn.Add(1)
		st.udpBytesIn.Add(uint64(len(payload)))
		agent := st.getAgentUDPAddr()
		if agent == nil || !addrEqual(agent, addr) {
			return
		}
		st.forwardAgentPayloadToPublic(route, client, payload, addr, enqueueWait, "DATAEnc2")
	case udputil.MsgDataEnc2Seq:
		if encNone {
			return
		}
		_, route, client, payload, _, ok := udputil.DecodeDataEnc2WithSeq(st.udpKeys, pkt)
		if !ok {
			st.udpDecodeDrops.Add(1)
			traceUDPf("udp: DATAEnc2Seq decode failed from=%v", addr)
			st.dashErrorRateLimited(dashSystemRoute, "error_udp_dataenc2seq_decode", hostFromAddr(addr), "", "", 1*time.Second)
			return
		}
		st.udpPacketsIn.Add(1)
		st.udpBytesIn.Add(uint64(len(payload)))
		agent := st.getAgentUDPAddr()
		if agent == nil || !addrEqual(agent, addr) {
			return
		}
		st.forwardAgentPayloadToPublic(route, client, payload, addr, enqueueWait, "DATAEnc2Seq")
	}
}

func (st *serverState) forwardAgentPayloadToPublic(route, client string, payload []byte, srcAddr net.Addr, enqueueWait time.Duration, label string) {
	if st.udpMaxPayload > 0 && len(payload) > st.udpMaxPayload {
		st.udpPayloadTooLargeDrops.Add(1)
		st.udpPublicWriteDrops.Add(1)
		st.dashErrorRateLimited(route, "loss_udp_public_payload_too_large", hostFromAddr(srcAddr), "", fmt.Sprintf("payload %d > max %d", len(payload), st.udpMaxPayload), 1*time.Second)
		traceUDPf("udp: %s payload too large route=%s size=%d max=%d", label, route, len(payload), st.udpMaxPayload)
		return
	}

	ua := st.resolveUDP(client)
	if ua == nil {
		st.udpResolveDrops.Add(1)
		return
	}

	if st.udpDirectRelay {
		pc := st.publicUDP[route]
		if pc == nil {
			traceUDPf("udp: %s unknown route=%s from=%v", label, route, srcAddr)
			st.dashErrorRateLimited(route, "error_udp_unknown_route", hostFromAddr(srcAddr), "", "", 1*time.Second)
			return
		}
		_, err := pc.WriteTo(payload, ua)
		if err != nil {
			if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
				_, err = pc.WriteTo(payload, ua)
			}
		}
		if err != nil {
			st.udpPublicWriteErrors.Add(1)
			st.udpPublicWriteDrops.Add(1)
			st.dashErrorRateLimited(route, "loss_udp_public_write_failed", hostFromAddr(ua), "", err.Error(), 1*time.Second)
			traceUDPf("udp: %s direct public write failed route=%s to=%v err=%v", label, route, ua, err)
			return
		}
		st.udpPacketsOut.Add(1)
		st.udpBytesOut.Add(uint64(len(payload)))
		if st.dash != nil {
			st.dash.addBytes(time.Now(), int64(len(payload)))
		}
		return
	}

	writeQueue := st.udpPublicWriters[route]
	if writeQueue == nil {
		traceUDPf("udp: %s unknown route=%s from=%v", label, route, srcAddr)
		st.dashErrorRateLimited(route, "error_udp_unknown_route", hostFromAddr(srcAddr), "", "", 1*time.Second)
		return
	}

	bufPtr := payloadPool.Get().(*[]byte)
	buf := *bufPtr
	if cap(buf) < len(payload) {
		buf = make([]byte, len(payload))
		*bufPtr = buf
	}
	buf = buf[:len(payload)]
	copy(buf, payload)
	if !writeQueue.EnqueueWithTimeout(buf, ua, bufPtr, enqueueWait) {
		payloadPool.Put(bufPtr)
		st.udpPublicWriteDrops.Add(1)
		st.dashErrorRateLimited(route, "loss_udp_route_public_write_queue", hostFromAddr(srcAddr), "", "route public write queue full", 1*time.Second)
		traceUDPf("udp: %s write queue full route=%s to=%v", label, route, ua)
	}
}

func (st *serverState) acceptPublicUDP(ctx context.Context, pc net.PacketConn, routeName string) error {
	// Determine worker count from config, environment, or defaults
	workers := runtime.NumCPU() * 4 // Increased from 2x to 4x for high-load
	if workers < 16 {
		workers = 16 // Increased minimum
	}
	if workers > 256 {
		workers = 256 // Increased max
	}
	if st.cfg.UDPWorkerCount != nil && *st.cfg.UDPWorkerCount > 0 {
		workers = *st.cfg.UDPWorkerCount
	} else if numWorkers := os.Getenv("HOSTIT_UDP_WORKERS"); numWorkers != "" {
		if n, err := strconv.Atoi(numWorkers); err == nil && n > 0 && n <= 256 {
			workers = n
		}
	}

	// Large buffer to absorb bursts without dropping packets.
	jobBufSize := 131072
	if st.cfg.UDPQueueSize != nil && *st.cfg.UDPQueueSize > 0 {
		jobBufSize = *st.cfg.UDPQueueSize
	}
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

	// Multiple readers to avoid single-reader bottleneck
	// Increased reader count for better parallelism
	numReaders := runtime.NumCPU()
	if numReaders < 4 {
		numReaders = 4
	}
	if numReaders > 32 {
		numReaders = 32 // Increased cap
	}
	if st.cfg.UDPReaderCount != nil && *st.cfg.UDPReaderCount > 0 {
		numReaders = *st.cfg.UDPReaderCount
	}

	readerDone := make(chan struct{})
	var readerWg sync.WaitGroup
	enqueueWait := time.Duration(envIntBound("HOSTIT_UDP_ENQUEUE_WAIT_US", 5000, 0, 50000)) * time.Microsecond

	for i := 0; i < numReaders; i++ {
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			// Per-reader buffer pool to avoid contention
			localPool := &sync.Pool{
				New: func() any {
					b := make([]byte, 64*1024)
					return &b
				},
			}

			for {
				select {
				case <-readerDone:
					return
				default:
				}

				bufPtr := localPool.Get().(*[]byte)
				buf := *bufPtr
				n, clientAddr, err := pc.ReadFrom(buf)
				if err != nil {
					localPool.Put(bufPtr)
					if ctx.Err() != nil {
						return
					}
					if errors.Is(err, net.ErrClosed) {
						return
					}
					if ne, ok := err.(net.Error); ok && (ne.Temporary() || ne.Timeout()) {
						continue
					}
					st.dashError(routeName, "error_accept_public_udp", "", "", err.Error())
					return
				}

				job := udpJob{data: buf, len: n, addr: clientAddr, bufPtr: bufPtr, pool: localPool, enq: time.Now()}
				enqueued := false
				select {
				case jobs <- job:
					enqueued = true
				default:
					if enqueueWait > 0 {
						t := time.NewTimer(enqueueWait)
						select {
						case jobs <- job:
							enqueued = true
						case <-t.C:
						}
						t.Stop()
					}
				}
				if !enqueued {
					st.udpPublicDrops.Add(1)
					st.dashErrorRateLimited(routeName, "loss_udp_public_reader_overload", hostFromAddr(clientAddr), "", "public UDP reader dropped packet (worker queue full)", 1*time.Second)
					localPool.Put(bufPtr)
				}
			}
		}()
	}

	// Wait for context cancellation
	<-ctx.Done()
	close(readerDone)
	readerWg.Wait()
	close(jobs)
	return nil
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
			budget := adaptiveBudget(st.udpQueueBaseBudget, st.udpQueueTightBudget, len(jobs), cap(jobs), st.udpQueueHighWater)
			if budget > 0 && !job.enq.IsZero() && time.Since(job.enq) > budget {
				st.udpPublicDrops.Add(1)
				st.dashErrorRateLimited(routeName, "loss_udp_public_worker_stale", hostFromAddr(job.addr), "", "public UDP worker dropped stale packet", 1*time.Second)
				if job.bufPtr != nil && job.pool != nil {
					job.pool.Put(job.bufPtr)
				}
				continue
			}
			pkt := job.data
			if job.len > 0 && job.len < len(pkt) {
				pkt = pkt[:job.len]
			}
			st.processPublicUDPPacket(pkt, job.addr, routeName)
			// Return buffer to the correct pool after processing
			if job.bufPtr != nil && job.pool != nil {
				job.pool.Put(job.bufPtr)
			}
		}
	}
}

// sendIndividual is a fallback for non-Linux platforms or when sendmmsg is unavailable.
func sendIndividual(pc net.PacketConn, packets [][]byte, addrs []net.Addr) (int, error) {
	sent := 0
	for i, pkt := range packets {
		_, err := pc.WriteTo(pkt, addrs[i])
		if err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// udpPublicWriter handles async writes to public clients (server→public path).
// Uses Go's native WriteTo which properly handles EAGAIN via the netpoller.
// This prevents blocking on slow clients and absorbs traffic bursts via the queue.
func (st *serverState) udpPublicWriter(ctx context.Context, pc net.PacketConn, queue *udpWriteQueueWithBackpressure, routeName string) {
	for {
		job, ok := queue.Dequeue(ctx)
		if !ok {
			return
		}
		budget := adaptiveBudget(st.udpQueueBaseBudget, st.udpQueueTightBudget, int(queue.depth.Load()), queue.capacity, st.udpQueueHighWater)
		if budget > 0 && !job.enqueue.IsZero() && time.Since(job.enqueue) > budget {
			st.udpPublicWriteDrops.Add(1)
			st.dashErrorRateLimited(routeName, "loss_udp_public_stale_queue", hostFromAddr(job.addr), "", "public UDP writer dropped stale packet", 1*time.Second)
			if job.bufPtr != nil {
				payloadPool.Put(job.bufPtr)
			}
			continue
		}

		_, err := pc.WriteTo(job.data, job.addr)
		if err != nil {
			if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
				_, err = pc.WriteTo(job.data, job.addr)
			}
			if err != nil {
				st.udpPublicWriteErrors.Add(1)
				st.udpPublicWriteDrops.Add(1)
				st.dashErrorRateLimited(routeName, "loss_udp_public_write_failed", hostFromAddr(job.addr), "", err.Error(), 1*time.Second)
				traceUDPf("udp: public write failed route=%s to=%v err=%v", routeName, job.addr, err)
			}
		} else {
			st.udpPacketsOut.Add(1)
			st.udpBytesOut.Add(uint64(len(job.data)))
			queue.totalBytes.Add(uint64(len(job.data)))
			queue.totalWrites.Add(1)
			if st.dash != nil {
				st.dash.addBytes(time.Now(), int64(len(job.data)))
			}
		}
		// Return buffer to payloadPool
		if job.bufPtr != nil {
			payloadPool.Put(job.bufPtr)
		}
	}
}

// udpAgentWriter handles async writes to the agent (server→agent path).
// Uses Go's native WriteTo which properly handles EAGAIN via the netpoller.
// The async queue absorbs bursts and prevents worker starvation.
func (st *serverState) udpAgentWriter(ctx context.Context, pc net.PacketConn) {
	for {
		job, ok := st.udpAgentWriteQueue.Dequeue(ctx)
		if !ok {
			return
		}
		budget := adaptiveBudget(st.udpQueueBaseBudget, st.udpQueueTightBudget, int(st.udpAgentWriteQueue.depth.Load()), st.udpAgentWriteQueue.capacity, st.udpQueueHighWater)
		if budget > 0 && !job.enqueue.IsZero() && time.Since(job.enqueue) > budget {
			st.udpAgentWriteDrops.Add(1)
			st.dashErrorRateLimited(dashSystemRoute, "loss_udp_agent_stale_queue", hostFromAddr(job.addr), "", "agent UDP writer dropped stale packet", 1*time.Second)
			if job.bufPtr != nil {
				udputil.PutOutputBuffer(job.bufPtr)
			}
			continue
		}

		_, err := pc.WriteTo(job.data, job.addr)
		if err != nil {
			if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
				_, err = pc.WriteTo(job.data, job.addr)
			}
			if err != nil {
				st.udpAgentWriteErrors.Add(1)
				st.udpAgentWriteDrops.Add(1)
				st.dashErrorRateLimited(dashSystemRoute, "loss_udp_agent_write_failed", hostFromAddr(job.addr), "", err.Error(), 1*time.Second)
				traceUDPf("udp: agent write failed to=%v err=%v", job.addr, err)
			}
		} else {
			st.udpPacketsOut.Add(1)
			st.udpBytesOut.Add(uint64(len(job.data)))
			st.udpAgentWriteQueue.totalBytes.Add(uint64(len(job.data)))
			st.udpAgentWriteQueue.totalWrites.Add(1)
			if st.dash != nil {
				st.dash.addBytes(time.Now(), int64(len(job.data)))
			}
		}
		// Return buffer to outPool
		if job.bufPtr != nil {
			udputil.PutOutputBuffer(job.bufPtr)
		}
	}
}

func (st *serverState) processPublicUDPPacket(pkt []byte, clientAddr net.Addr, routeName string) {
	enqueueWait := st.udpEnqueueWait
	// Check if route is enabled
	if !st.routeEnabled(routeName) {
		st.udpRouteDisabledDrops.Add(1)
		return // Silently drop packets for disabled routes
	}

	agent := st.getAgentUDPAddr()
	if agent == nil {
		st.udpNoAgentDrops.Add(1)
		st.dashErrorRateLimited(routeName, "error_udp_no_agent", "", "", "", 1*time.Second)
		return
	}

	st.udpPacketsIn.Add(1)
	st.udpBytesIn.Add(uint64(len(pkt)))

	if st.udpMaxPayload > 0 && len(pkt) > st.udpMaxPayload {
		st.udpPayloadTooLargeDrops.Add(1)
		st.udpAgentWriteDrops.Add(1)
		st.dashErrorRateLimited(routeName, "loss_udp_payload_too_large", hostFromAddr(clientAddr), "", fmt.Sprintf("payload=%d max=%d", len(pkt), st.udpMaxPayload), 1*time.Second)
		return
	}

	var msg []byte
	var bufPtr *[]byte // For pooled encoding
	clientAddrStr := clientAddr.String()
	seq := st.udpSeqToAgent.Add(1)
	if st.encryptionNone || !st.udpKeys.Enabled() {
		msg = udputil.EncodeDataWithSeq(seq, routeName, clientAddrStr, pkt)
	} else {
		kid := st.getAgentUDPKeyID()
		if kid == 0 {
			kid = st.cfg.UDPKeyID
		}
		// Use pooled encoding for zero-allocation encryption
		msg, bufPtr = udputil.EncodeDataEnc2PooledWithSeq(st.udpKeys, kid, seq, routeName, clientAddrStr, pkt)
	}

	if st.udpDirectRelay {
		if st.udpData == nil {
			st.udpNoAgentDrops.Add(1)
			if bufPtr != nil {
				udputil.PutOutputBuffer(bufPtr)
			}
			return
		}
		_, err := st.udpData.WriteTo(msg, agent)
		if err != nil {
			if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
				_, err = st.udpData.WriteTo(msg, agent)
			}
		}
		if err != nil {
			st.udpAgentWriteErrors.Add(1)
			st.udpAgentWriteDrops.Add(1)
			st.dashErrorRateLimited(routeName, "loss_udp_agent_write_failed", hostFromAddr(agent), "", err.Error(), 1*time.Second)
			traceUDPf("udp: direct agent write failed route=%s err=%v", routeName, err)
		} else {
			st.udpPacketsOut.Add(1)
			st.udpBytesOut.Add(uint64(len(msg)))
			if st.dash != nil {
				st.dash.addBytes(time.Now(), int64(len(msg)))
			}
		}
		if bufPtr != nil {
			udputil.PutOutputBuffer(bufPtr)
		}
	} else if st.udpAgentWriteQueue == nil || !st.udpAgentWriteQueue.EnqueueWithTimeout(msg, agent, bufPtr, enqueueWait) {
		st.udpAgentWriteDrops.Add(1)
		st.dashErrorRateLimited(routeName, "loss_udp_agent_write_queue", hostFromAddr(agent), "", "agent write queue full", 1*time.Second)
		traceUDPf("udp: agent write queue full route=%s", routeName)
		if bufPtr != nil {
			udputil.PutOutputBuffer(bufPtr)
		}
	}

	// Stats + dashboard tracking — kept off the critical write path.
	// Only call time.Now() once, and only when dashboard is active.
	if st.dash != nil {
		now := time.Now()
		st.dash.addBytes(now, int64(len(pkt)))
	}
	if st.udpStats != nil {
		// Track session stats with single lock acquisition.
		clientIP := hostFromAddr(clientAddr)
		sessionID := routeName + ":" + clientIP
		info := st.udpStats.GetOrCreate(sessionID, routeName, clientIP, "")
		info.Stats.RecordReceive(len(pkt))
		info.TouchActivity()
		// Log first-seen events to dashboard.
		if st.dash != nil && info.Stats.PacketsReceived.Load() <= 1 {
			now := time.Now()
			st.dash.addConn(now)
			st.dash.addEvent(routeName, DashboardEvent{TimeUnix: now.Unix(), Kind: "udp_session", RemoteIP: clientIP, Detail: "new UDP client"})
		}
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
	// Tune kernel-level keepalive probes for faster dead-connection detection.
	// Without this, even with a 30s keepalive period the OS retries 9 times at
	// 75s intervals (Linux default) = 11+ minutes before a dead peer is detected.
	setTCPUserTimeout(tc, 15*time.Second)
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
