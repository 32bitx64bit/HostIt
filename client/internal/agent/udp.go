package agent

import (
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hostit/shared/logging"
	"hostit/shared/udputil"
)

var udpBufPool = sync.Pool{New: func() any {
	b := make([]byte, 64*1024)
	return &b
}}

type udpSession struct {
	conn   *net.UDPConn
	route  string
	client string
	close  sync.Once
}

// udpWriter handles writing packets to the server with buffer pooling.
type udpWriter struct {
	conn   *net.UDPConn
	stats  *udputil.Stats
	drops  atomic.Uint64
	writes atomic.Uint64

	// Congestion control state
	congestionMode    atomic.Bool
	lastDropTime      atomic.Int64
	congestionBackoff atomic.Int64 // nanoseconds to wait between sends

	// Queue depth monitoring
	queueDepth    atomic.Int32
	queueCapacity int
}

func newUDPWriter(conn *net.UDPConn, stats *udputil.Stats, queueCapacity int) *udpWriter {
	return &udpWriter{conn: conn, stats: stats, queueCapacity: queueCapacity}
}

// WritePooled writes an already-encoded packet. If bufPtr is non-nil, it returns the buffer to the pool after writing.
// NOTE: Removed congestion backoff sleep - it causes more harm than good by introducing
// latency that leads to queue overflow. Better to drop quickly than to block the writer.
func (w *udpWriter) WritePooled(data []byte, bufPtr *[]byte) error {
	_, err := w.conn.Write(data)
	if bufPtr != nil {
		udputil.PutOutputBuffer(bufPtr)
	}
	if err != nil {
		w.drops.Add(1)
		w.stats.RecordLoss(1)
		return err
	}
	w.writes.Add(1)
	w.stats.RecordSend(len(data))
	return nil
}

// Write writes a pre-encoded packet (no pooling).
// NOTE: Removed congestion backoff sleep - it causes more harm than good.
func (w *udpWriter) Write(data []byte) error {
	_, err := w.conn.Write(data)
	if err != nil {
		w.drops.Add(1)
		w.stats.RecordLoss(1)
		return err
	}
	w.writes.Add(1)
	w.stats.RecordSend(len(data))
	return nil
}

func (w *udpWriter) enterCongestionMode() {
	w.lastDropTime.Store(time.Now().UnixNano())
	if !w.congestionMode.Swap(true) {
		// Just entered congestion mode - start with 100µs backoff
		w.congestionBackoff.Store(100 * 1000) // 100 microseconds in nanoseconds
		log.Warn(logging.CatUDP, "UDP entering congestion mode - applying send backoff")
	}
}

func (w *udpWriter) maybeExitCongestionMode() {
	if !w.congestionMode.Load() {
		return
	}
	// Exit congestion mode after 5 seconds of no drops
	lastDrop := w.lastDropTime.Load()
	if time.Since(time.Unix(0, lastDrop)) > 5*time.Second {
		w.congestionMode.Store(false)
		w.congestionBackoff.Store(0)
		log.Info(logging.CatUDP, "UDP exited congestion mode")
		return
	}
	// Gradually reduce backoff
	currentBackoff := w.congestionBackoff.Load()
	if currentBackoff > 1000 { // Don't go below 1µs
		// Reduce by 10% every successful write
		newBackoff := currentBackoff - currentBackoff/10
		w.congestionBackoff.Store(newBackoff)
	}
}

// QueueDepth returns the current queue depth as a percentage.
func (w *udpWriter) QueueDepth() float64 {
	cap := w.queueCapacity
	if cap == 0 {
		return 0
	}
	return float64(w.queueDepth.Load()) / float64(cap) * 100
}

// CongestionMetrics returns current congestion state.
func (w *udpWriter) CongestionMetrics() (inCongestion bool, backoff time.Duration, queueDepthPct float64) {
	return w.congestionMode.Load(), time.Duration(w.congestionBackoff.Load()), w.QueueDepth()
}

// sendResult tracks the result of a packet send for backpressure.
type sendResult struct {
	err error
}

// outPacketWithResult wraps an outgoing packet with a result channel for backpressure.
type outPacketWithResult struct {
	data    []byte
	bufPtr  *[]byte
	result  chan sendResult
	enqueue time.Time // When the packet was enqueued (for latency tracking)
}

// udpWriteQueue manages a queue of packets with backpressure and multiple writers.
type udpWriteQueue struct {
	queue      chan outPacketWithResult
	stats      *udputil.Stats
	depth      atomic.Int32
	capacity   int
	drops      atomic.Uint64
	avgLatency atomic.Int64 // Average queue latency in nanoseconds
}

func newUDPWriteQueue(capacity int, stats *udputil.Stats) *udpWriteQueue {
	return &udpWriteQueue{
		queue:    make(chan outPacketWithResult, capacity),
		capacity: capacity,
		stats:    stats,
	}
}

// TryEnqueue attempts to enqueue a packet without blocking.
// Returns false if the queue is full (packet dropped).
func (q *udpWriteQueue) TryEnqueue(data []byte, bufPtr *[]byte) bool {
	pkt := outPacketWithResult{
		data:    data,
		bufPtr:  bufPtr,
		enqueue: time.Now(),
	}
	select {
	case q.queue <- pkt:
		q.depth.Add(1)
		return true
	default:
		q.drops.Add(1)
		q.stats.RecordLoss(1)
		if bufPtr != nil {
			udputil.PutOutputBuffer(bufPtr)
		}
		return false
	}
}

// EnqueueWithTimeout attempts to enqueue and waits up to timeout when full.
// Returns false if still full after waiting.
func (q *udpWriteQueue) EnqueueWithTimeout(data []byte, bufPtr *[]byte, timeout time.Duration) bool {
	if timeout <= 0 {
		return q.TryEnqueue(data, bufPtr)
	}
	pkt := outPacketWithResult{
		data:    data,
		bufPtr:  bufPtr,
		enqueue: time.Now(),
	}
	select {
	case q.queue <- pkt:
		q.depth.Add(1)
		return true
	default:
	}

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case q.queue <- pkt:
		q.depth.Add(1)
		return true
	case <-t.C:
		q.drops.Add(1)
		q.stats.RecordLoss(1)
		if bufPtr != nil {
			udputil.PutOutputBuffer(bufPtr)
		}
		return false
	}
}

// Dequeue returns the next packet to send.
func (q *udpWriteQueue) Dequeue(ctx context.Context) (outPacketWithResult, bool) {
	select {
	case pkt, ok := <-q.queue:
		if !ok {
			return outPacketWithResult{}, false
		}
		q.depth.Add(-1)
		// Track latency
		latency := time.Since(pkt.enqueue).Nanoseconds()
		// Simple moving average
		oldAvg := q.avgLatency.Load()
		if oldAvg == 0 {
			q.avgLatency.Store(latency)
		} else {
			// Weighted average: 90% old, 10% new
			newAvg := oldAvg - oldAvg/10 + latency/10
			q.avgLatency.Store(newAvg)
		}
		return pkt, true
	case <-ctx.Done():
		return outPacketWithResult{}, false
	}
}

// Depth returns current queue depth.
func (q *udpWriteQueue) Depth() int { return int(q.depth.Load()) }

// Capacity returns queue capacity.
func (q *udpWriteQueue) Capacity() int { return q.capacity }

// AvgLatency returns average queue latency.
func (q *udpWriteQueue) AvgLatency() time.Duration {
	return time.Duration(q.avgLatency.Load())
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

func adaptiveBudget(base, tight time.Duration, depth, capacity, highWaterPct int) time.Duration {
	if capacity <= 0 {
		return base
	}
	if depth*100 >= capacity*highWaterPct {
		return tight
	}
	return base
}

func runUDP(ctx context.Context, dataAddr string, token string, sec *udpSecurityState, routesByName map[string]RemoteRoute) {
	const idle = 2 * time.Minute
	const keepaliveEvery = 5 * time.Second

	// UDP stats for monitoring
	stats := udputil.NewStats()

	// Log stats periodically with congestion info
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s := stats.Snapshot()
				if s.PacketsReceived > 0 || s.PacketsSent > 0 {
					log.Infof(logging.CatUDP, "UDP stats: sent=%d recv=%d lost=%d loss=%.2f%%",
						s.PacketsSent, s.PacketsReceived, s.PacketsLost, s.LossRate*100)
				}
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		log.Debugf(logging.CatUDP, "dialing UDP server %s", dataAddr)
		c, err := net.Dial("udp", dataAddr)
		if err != nil {
			log.Warnf(logging.CatUDP, "UDP dial failed: %v", err)
			stats.RecordLoss(1)
			t := time.NewTimer(1 * time.Second)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			continue
		}
		log.Infof(logging.CatUDP, "UDP connection established to %s", dataAddr)
		log.Infof(logging.CatUDP, "UDP profile: fast (low-latency, drop-on-overload)")
		directRelay := true
		if v := os.Getenv("HOSTIT_UDP_DIRECT_RELAY"); strings.TrimSpace(v) != "" {
			lv := strings.ToLower(strings.TrimSpace(v))
			if lv == "0" || lv == "false" || lv == "no" || lv == "off" {
				directRelay = false
			}
		}
		if directRelay {
			log.Info(logging.CatUDP, "UDP relay mode: direct (immediate receive->send, minimal queueing)")
		} else {
			log.Info(logging.CatUDP, "UDP relay mode: queued (async writers + burst absorption)")
		}

		uc, ok := c.(*net.UDPConn)
		if !ok {
			_ = c.Close()
			return
		}
		// Set large UDP buffers with kernel verification.
		// 64MB improves burst absorption for high-FPS streaming workloads.
		const wantBuf = 64 * 1024 * 1024
		actualR, actualW := trySetUDPBuffers(uc, wantBuf)
		log.Infof(logging.CatUDP, "UDP buffers [server]: read=%d write=%d (requested %d)", actualR, actualW, wantBuf)
		if actualR > 0 && actualR < wantBuf {
			log.Warnf(logging.CatUDP, "UDP read buffer is only %d bytes (wanted %d). Run: sysctl -w net.core.rmem_max=%d", actualR, wantBuf, wantBuf)
		}
		if actualW > 0 && actualW < wantBuf {
			log.Warnf(logging.CatUDP, "UDP write buffer is only %d bytes (wanted %d). Run: sysctl -w net.core.wmem_max=%d", actualW, wantBuf, wantBuf)
		}

		// Create write queue with backpressure support
		queueCapacity := 131072
		if qStr := os.Getenv("HOSTIT_UDP_QUEUE"); qStr != "" {
			if q, err := strconv.Atoi(qStr); err == nil && q >= 4096 && q <= 1048576 {
				queueCapacity = q
			}
		}
		maxQueueLatencyMs := envIntBound("HOSTIT_UDP_MAX_QUEUE_LATENCY_MS", 0, 0, 5000)
		highWaterPct := envIntBound("HOSTIT_UDP_HIGH_WATER_PCT", 90, 50, 98)
		baseBudget := time.Duration(maxQueueLatencyMs) * time.Millisecond
		tightBudget := baseBudget / 2
		if baseBudget > 0 && tightBudget < 5*time.Millisecond {
			tightBudget = 5 * time.Millisecond
		}
		writeQueue := newUDPWriteQueue(queueCapacity, stats)
		enqueueWait := time.Duration(envIntBound("HOSTIT_UDP_ENQUEUE_WAIT_US", 20000, 0, 50000)) * time.Microsecond
		maxPayload := envIntBound("HOSTIT_UDP_MAX_PAYLOAD", 1400, 0, 65507)
		seqToServer := &udputil.SequenceCounter{}
		if maxPayload > 0 {
			log.Infof(logging.CatUDP, "UDP max payload cap enabled (agent->server): %d bytes", maxPayload)
		} else {
			log.Warn(logging.CatUDP, "UDP max payload cap disabled (agent->server); large packets may fragment and drop")
		}

		// Precompute UDP route local targets and resolved addresses to avoid per-packet
		// localTargetFromPublicAddr parsing and DNS/address resolution on the hot path.
		type udpRouteTarget struct {
			localTarget string
			raddr       *net.UDPAddr
		}
		udpTargets := map[string]udpRouteTarget{}
		for name, rt := range routesByName {
			if !routeHasUDP(rt.Proto) {
				continue
			}
			localTarget, ok := localTargetFromPublicAddr(rt.PublicAddr)
			if !ok {
				log.Warnf(logging.CatUDP, "UDP route target parse failed route=%s public=%q", name, rt.PublicAddr)
				continue
			}
			raddr, err := net.ResolveUDPAddr("udp", localTarget)
			if err != nil {
				log.Warnf(logging.CatUDP, "UDP route target resolve failed route=%s target=%s: %v", name, localTarget, err)
				continue
			}
			udpTargets[name] = udpRouteTarget{localTarget: localTarget, raddr: raddr}
		}

		// Register so the server learns our UDP address.
		ks := sec.Get()
		if ks.Enabled() {
			if _, err := uc.Write(udputil.EncodeRegEnc2(ks, token)); err != nil {
				stats.RecordLoss(1)
				log.Warnf(logging.CatUDP, "UDP register write failed (enc): %v", err)
			}
		} else {
			if _, err := uc.Write(udputil.EncodeReg(token)); err != nil {
				stats.RecordLoss(1)
				log.Warnf(logging.CatUDP, "UDP register write failed: %v", err)
			}
		}

		// Keepalive: some NATs expire UDP mappings quickly (often ~10-30s) when idle
		// or when traffic is primarily one-way. Periodically re-register to keep the
		// mapping alive and refresh the server-side observed agent UDP address.
		kaDone := make(chan struct{})
		go func() {
			t := time.NewTicker(keepaliveEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-kaDone:
					return
				case <-t.C:
					ks := sec.Get()
					if ks.Enabled() {
						if _, err := uc.Write(udputil.EncodeRegEnc2(ks, token)); err != nil {
							stats.RecordLoss(1)
							log.Warnf(logging.CatUDP, "UDP keepalive write failed (enc): %v", err)
						}
					} else {
						if _, err := uc.Write(udputil.EncodeReg(token)); err != nil {
							stats.RecordLoss(1)
							log.Warnf(logging.CatUDP, "UDP keepalive write failed: %v", err)
						}
					}
				}
			}
		}()

		// Create sub-context for this connection's workers
		connCtx, connCancel := context.WithCancel(ctx)
		_ = connCancel // Used to cancel workers on connection close

		sessionsMu := sync.RWMutex{}
		sessions := map[string]map[string]*udpSession{} // route -> client -> session

		var writerWg sync.WaitGroup
		if !directRelay {
			// Multiple writer goroutines reduce single-writer bottleneck under heavy load.
			writerWorkers := runtimeNumCPU()
			if writerWorkers < 2 {
				writerWorkers = 2
			}
			if writerWorkers > 64 {
				writerWorkers = 64
			}
			if nStr := os.Getenv("HOSTIT_UDP_WRITE_WORKERS"); nStr != "" {
				if n, err := strconv.Atoi(nStr); err == nil && n >= 1 && n <= 128 {
					writerWorkers = n
				}
			}
			writerWg.Add(writerWorkers)
			for i := 0; i < writerWorkers; i++ {
				go func() {
					defer writerWg.Done()
					for {
						pkt, ok := writeQueue.Dequeue(connCtx)
						if !ok {
							return
						}
						if !pkt.enqueue.IsZero() {
							budget := adaptiveBudget(baseBudget, tightBudget, writeQueue.Depth(), writeQueue.Capacity(), highWaterPct)
							if budget > 0 && time.Since(pkt.enqueue) > budget {
								stats.RecordLoss(1)
								if pkt.bufPtr != nil {
									udputil.PutOutputBuffer(pkt.bufPtr)
								}
								continue
							}
						}
						if _, err := uc.Write(pkt.data); err != nil {
							if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
								_, err = uc.Write(pkt.data)
							}
							if err != nil {
								stats.RecordLoss(1)
							}
						} else {
							stats.RecordSend(len(pkt.data))
						}
						if pkt.bufPtr != nil {
							udputil.PutOutputBuffer(pkt.bufPtr)
						}
					}
				}()
			}

			// Queue depth monitor - logs warnings when queue is getting full
			go func() {
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-connCtx.Done():
						return
					case <-ticker.C:
						depth := writeQueue.Depth()
						capacity := writeQueue.Capacity()
						pct := float64(depth) / float64(capacity) * 100
						if pct > 80 {
							log.Warnf(logging.CatUDP, "UDP write queue high: %d/%d (%.1f%%), avg latency=%v",
								depth, capacity, pct, writeQueue.AvgLatency())
						}
					}
				}
			}()
		}

		getOrCreate := func(routeName, clientAddr string, target udpRouteTarget) (*udpSession, bool) {
			// RLock fast-path: most packets go to existing sessions.
			sessionsMu.RLock()
			if m := sessions[routeName]; m != nil {
				if s := m[clientAddr]; s != nil {
					sessionsMu.RUnlock()
					return s, true
				}
			}
			sessionsMu.RUnlock()

			// Slow path: create new session under write lock with double-check.
			sessionsMu.Lock()
			m := sessions[routeName]
			if m == nil {
				m = map[string]*udpSession{}
				sessions[routeName] = m
			}
			if s := m[clientAddr]; s != nil {
				// Another goroutine created the session first.
				sessionsMu.Unlock()
				return s, true
			}

			lc := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
			lconn, err := net.DialUDP("udp", lc, target.raddr)
			if err != nil {
				sessionsMu.Unlock()
				log.Warnf(logging.CatUDP, "UDP local dial failed route=%s target=%s: %v", routeName, target.localTarget, err)
				stats.RecordLoss(1)
				return nil, false
			}
			_ = lconn.SetReadBuffer(8 * 1024 * 1024)  // Increased from 4MB to 8MB
			_ = lconn.SetWriteBuffer(8 * 1024 * 1024) // Increased from 4MB to 8MB
			s := &udpSession{conn: lconn, route: routeName, client: clientAddr}
			m[clientAddr] = s
			sessionsMu.Unlock()
			log.Debugf(logging.CatUDP, "new UDP session route=%s client=%s target=%s", routeName, clientAddr, target.localTarget)

			go func() {
				localBufPtr := udpBufPool.Get().(*[]byte)
				localBuf := *localBufPtr
				defer udpBufPool.Put(localBufPtr)
				// Cache the KeySet — it rarely changes (only on key rotation).
				// Re-check periodically rather than on every packet.
				cachedKS := sec.Get()
				pktCount := 0

				// Track last activity for race-free shutdown
				lastActivity := time.Now()
				const shutdownGracePeriod = 100 * time.Millisecond

				for {
					_ = lconn.SetReadDeadline(time.Now().Add(idle))
					n, err := lconn.Read(localBuf)
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Timeout() {
							break
						}
						break
					}

					// Check if we're shutting down (race condition fix)
					select {
					case <-connCtx.Done():
						// Connection is closing, but we got a packet - try to send it
						// with a short grace period
					default:
					}

					lastActivity = time.Now()

					// Refresh KeySet every ~1000 packets to pick up rotations without per-packet RLock.
					pktCount++
					if pktCount >= 1000 {
						cachedKS = sec.Get()
						pktCount = 0
					}

					// Use pooled encoding for zero-allocation encryption
					var encoded []byte
					var bufPtr *[]byte
					if maxPayload > 0 && n > maxPayload {
						stats.RecordLoss(1)
						continue
					}
					seq := seqToServer.Next()
					if cachedKS.Enabled() {
						encoded, bufPtr = udputil.EncodeDataEnc2PooledWithSeq(cachedKS, cachedKS.CurID, seq, routeName, clientAddr, localBuf[:n])
					} else {
						encoded = udputil.EncodeDataWithSeq(seq, routeName, clientAddr, localBuf[:n])
					}

					if directRelay {
						if _, err := uc.Write(encoded); err != nil {
							if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
								_, err = uc.Write(encoded)
							}
							if err != nil {
								stats.RecordLoss(1)
							}
						} else {
							stats.RecordSend(len(encoded))
						}
						if bufPtr != nil {
							udputil.PutOutputBuffer(bufPtr)
						}
					} else {
						if !writeQueue.EnqueueWithTimeout(encoded, bufPtr, enqueueWait) {
							stats.RecordLoss(1)
						}
					}
				}

				// Graceful shutdown: wait briefly for any in-flight packets
				shutdownStart := time.Now()
				for time.Since(shutdownStart) < shutdownGracePeriod && time.Since(lastActivity) < shutdownGracePeriod {
					time.Sleep(10 * time.Millisecond)
				}

				s.close.Do(func() {
					_ = lconn.Close()
				})
				log.Debugf(logging.CatUDP, "UDP session closed route=%s client=%s", routeName, clientAddr)
				sessionsMu.Lock()
				if mm := sessions[routeName]; mm != nil {
					delete(mm, clientAddr)
					if len(mm) == 0 {
						delete(sessions, routeName)
					}
				}
				sessionsMu.Unlock()
			}()

			return s, true
		}

		// Determine worker count for incoming packet processing
		inWorkers := runtimeNumCPU() * 4 // Increased from 2x to 4x
		if inWorkers < 16 {
			inWorkers = 16 // Increased minimum
		}
		if inWorkers > 256 {
			inWorkers = 256
		}
		if numWorkers := os.Getenv("HOSTIT_UDP_WORKERS"); numWorkers != "" {
			if n, err := strconv.Atoi(numWorkers); err == nil && n > 0 && n <= 256 {
				inWorkers = n
			}
		}

		// Job queue for incoming packets - larger buffer for high-load scenarios
		type inJob struct {
			data   []byte
			len    int
			bufPtr *[]byte
			pool   *sync.Pool // Pool to return buffer to (must match the pool it came from)
			enq    time.Time
		}
		inJobs := make(chan inJob, queueCapacity)

		// Start multiple reader goroutines for the main socket
		// This is the key fix: multiple readers prevent the single-reader bottleneck
		var readerWg sync.WaitGroup
		numReaders := runtimeNumCPU()
		if numReaders < 4 {
			numReaders = 4
		}
		if numReaders > 32 {
			numReaders = 32
		}

		readerDone := make(chan struct{})
		for i := 0; i < numReaders; i++ {
			readerWg.Add(1)
			go func() {
				defer readerWg.Done()
				localBufPool := &sync.Pool{
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

					bufPtr := localBufPool.Get().(*[]byte)
					buf := *bufPtr
					n, err := uc.Read(buf)
					if err != nil {
						localBufPool.Put(bufPtr)
						if connCtx.Err() != nil {
							return
						}
						continue
					}

					job := inJob{data: buf, len: n, bufPtr: bufPtr, pool: localBufPool, enq: time.Now()}
					enqueued := false
					select {
					case inJobs <- job:
						enqueued = true
					default:
						if enqueueWait > 0 {
							t := time.NewTimer(enqueueWait)
							select {
							case inJobs <- job:
								enqueued = true
							case <-t.C:
							}
							t.Stop()
						}
					}
					if !enqueued {
						stats.RecordLoss(1)
						localBufPool.Put(bufPtr)
					}
				}
			}()
		}

		// Worker pool for incoming packets — parallelizes decrypt + route + write
		var inWg sync.WaitGroup
		inWg.Add(inWorkers)
		for i := 0; i < inWorkers; i++ {
			go func() {
				defer inWg.Done()
				cachedKS := sec.Get()
				pkts := 0
				for job := range inJobs {
					if !job.enq.IsZero() {
						budget := adaptiveBudget(baseBudget, tightBudget, len(inJobs), cap(inJobs), highWaterPct)
						if budget > 0 && time.Since(job.enq) > budget {
							stats.RecordLoss(1)
							if job.bufPtr != nil && job.pool != nil {
								job.pool.Put(job.bufPtr)
							}
							continue
						}
					}
					pkt := job.data[:job.len]
					pkts++
					if pkts >= 1000 {
						cachedKS = sec.Get()
						pkts = 0
					}
					var (
						routeName  string
						clientAddr string
						payload    []byte
						ok         bool
					)
					if cachedKS.Enabled() {
						if len(pkt) > 0 && pkt[0] == udputil.MsgDataEnc2Seq {
							_, routeName, clientAddr, payload, _, ok = udputil.DecodeDataEnc2WithSeq(cachedKS, pkt)
						} else {
							routeName, clientAddr, payload, _, ok = udputil.DecodeDataEnc2(cachedKS, pkt)
						}
						if !ok {
							stats.RecordLoss(1)
							if job.bufPtr != nil && job.pool != nil {
								job.pool.Put(job.bufPtr)
							}
							continue
						}
					} else {
						if len(pkt) > 0 && pkt[0] == udputil.MsgDataSeq {
							_, routeName, clientAddr, payload, ok = udputil.DecodeDataWithSeq(pkt)
						} else {
							routeName, clientAddr, payload, ok = udputil.DecodeData(pkt)
						}
						if !ok {
							stats.RecordLoss(1)
							if job.bufPtr != nil && job.pool != nil {
								job.pool.Put(job.bufPtr)
							}
							continue
						}
					}
					target, ok := udpTargets[routeName]
					if !ok {
						stats.RecordLoss(1)
						log.Debugf(logging.CatUDP, "UDP packet dropped: unknown route=%s", routeName)
						if job.bufPtr != nil && job.pool != nil {
							job.pool.Put(job.bufPtr)
						}
						continue
					}
					s, ok := getOrCreate(routeName, clientAddr, target)
					if !ok || s == nil {
						stats.RecordLoss(1)
						if job.bufPtr != nil && job.pool != nil {
							job.pool.Put(job.bufPtr)
						}
						continue
					}
					if _, err := s.conn.Write(payload); err != nil {
						stats.RecordLoss(1)
					} else {
						stats.RecordReceive(len(payload))
					}
					if job.bufPtr != nil && job.pool != nil {
						job.pool.Put(job.bufPtr)
					}
				}
			}()
		}

		// Wait for context cancellation
		<-connCtx.Done()

		// Signal readers to stop
		close(readerDone)
		_ = uc.Close() // This will unblock readers
		readerWg.Wait()

		close(inJobs)
		inWg.Wait()

		if !directRelay {
			close(writeQueue.queue)
			writerWg.Wait()
		}

		close(kaDone)
		log.Info(logging.CatUDP, "UDP connection closed, reconnecting...")

		// Backoff and retry.
		t := time.NewTimer(1 * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// runtimeNumCPU returns the number of CPUs available to the process.
func runtimeNumCPU() int {
	return runtime.NumCPU()
}
