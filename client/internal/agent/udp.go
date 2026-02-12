package agent

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"hostit/client/internal/udpproto"
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
}

func newUDPWriter(conn *net.UDPConn, stats *udputil.Stats) *udpWriter {
	return &udpWriter{conn: conn, stats: stats}
}

// WritePooled writes an already-encoded packet. If bufPtr is non-nil, it returns the buffer to the pool after writing.
func (w *udpWriter) WritePooled(data []byte, bufPtr *[]byte) error {
	_, err := w.conn.Write(data)
	if bufPtr != nil {
		udpproto.PutOutputBuffer(bufPtr)
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

func runUDP(ctx context.Context, dataAddr string, token string, sec *udpSecurityState, routesByName map[string]RemoteRoute) {
	const idle = 2 * time.Minute
	const keepaliveEvery = 5 * time.Second

	// UDP stats for monitoring
	stats := udputil.NewStats()

	// Log stats periodically
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

		uc, ok := c.(*net.UDPConn)
		if !ok {
			_ = c.Close()
			return
		}
		// Set large UDP buffers with kernel verification.
		// Increased from 8MB to 16MB for high-load streaming scenarios.
		const wantBuf = 16 * 1024 * 1024
		actualR, actualW := trySetUDPBuffers(uc, wantBuf)
		log.Infof(logging.CatUDP, "UDP buffers [server]: read=%d write=%d (requested %d)", actualR, actualW, wantBuf)
		if actualR > 0 && actualR < wantBuf/2 {
			log.Warnf(logging.CatUDP, "UDP read buffer is only %d bytes (wanted %d). Run: sysctl -w net.core.rmem_max=%d", actualR, wantBuf, wantBuf)
		}
		if actualW > 0 && actualW < wantBuf/2 {
			log.Warnf(logging.CatUDP, "UDP write buffer is only %d bytes (wanted %d). Run: sysctl -w net.core.wmem_max=%d", actualW, wantBuf, wantBuf)
		}

		// Create writer for outgoing packets
		writer := newUDPWriter(uc, stats)

		// Register so the server learns our UDP address.
		ks := sec.Get()
		if ks.Enabled() {
			_, _ = uc.Write(udpproto.EncodeRegEnc2(ks, token))
		} else {
			_, _ = uc.Write(udpproto.EncodeReg(token))
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
						_, _ = uc.Write(udpproto.EncodeRegEnc2(ks, token))
					} else {
						_, _ = uc.Write(udpproto.EncodeReg(token))
					}
				}
			}
		}()

		// Create sub-context for this connection's workers
		connCtx, connCancel := context.WithCancel(ctx)
		_ = connCancel // Used to cancel workers on connection close

		sessionsMu := sync.RWMutex{}
		sessions := map[string]map[string]*udpSession{} // route -> client -> session

		// Outgoing packet queue - workers put packets here for the single writer
		// This ensures we don't have multiple goroutines writing to the same socket
		type outPacket struct {
			data   []byte
			bufPtr *[]byte // nil if data is not from pool
		}
		outQueue := make(chan outPacket, 65536) // Increased from 16384 to 65536 for high-load

		// Single writer goroutine - serializes all writes to the socket
		var writerWg sync.WaitGroup
		writerWg.Add(1)
		go func() {
			defer writerWg.Done()
			for {
				select {
				case <-connCtx.Done():
					return
				case pkt, ok := <-outQueue:
					if !ok {
						return
					}
					writer.WritePooled(pkt.data, pkt.bufPtr)
				}
			}
		}()

		getOrCreate := func(routeName, clientAddr, localTarget string) (*udpSession, bool) {
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
				sessionsMu.Unlock()
				return s, true
			}

			raddr, err := net.ResolveUDPAddr("udp", localTarget)
			if err != nil {
				sessionsMu.Unlock()
				log.Warnf(logging.CatUDP, "UDP resolve failed route=%s client=%s target=%s: %v", routeName, clientAddr, localTarget, err)
				stats.RecordLoss(1)
				return nil, false
			}
			lc := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
			lconn, err := net.DialUDP("udp", lc, raddr)
			if err != nil {
				sessionsMu.Unlock()
				log.Warnf(logging.CatUDP, "UDP local dial failed route=%s target=%s: %v", routeName, localTarget, err)
				stats.RecordLoss(1)
				return nil, false
			}
			_ = lconn.SetReadBuffer(8 * 1024 * 1024)  // Increased from 4MB to 8MB
			_ = lconn.SetWriteBuffer(8 * 1024 * 1024) // Increased from 4MB to 8MB
			s := &udpSession{conn: lconn, route: routeName, client: clientAddr}
			m[clientAddr] = s
			sessionsMu.Unlock()
			log.Debugf(logging.CatUDP, "new UDP session route=%s client=%s target=%s", routeName, clientAddr, localTarget)

			go func() {
				localBufPtr := udpBufPool.Get().(*[]byte)
				localBuf := *localBufPtr
				defer udpBufPool.Put(localBufPtr)
				// Cache the KeySet — it rarely changes (only on key rotation).
				// Re-check periodically rather than on every packet.
				cachedKS := sec.Get()
				pktCount := 0

				// Use a timer-based idle timeout instead of SetReadDeadline per
				// packet. This eliminates 2 syscalls (time.Now + setsockopt) on
				// every read in the hot path. The timer resets after each packet.
				idleTimer := time.AfterFunc(idle, func() {
					s.close.Do(func() { _ = lconn.Close() })
				})
				defer idleTimer.Stop()

				for {
					n, err := lconn.Read(localBuf)
					if err != nil {
						break
					}
					idleTimer.Reset(idle)
					// Refresh KeySet every ~1000 packets to pick up rotations without per-packet RLock.
					pktCount++
					if pktCount >= 1000 {
						cachedKS = sec.Get()
						pktCount = 0
					}

					// Use pooled encoding for zero-allocation encryption
					var pkt outPacket
					if cachedKS.Enabled() {
						encoded, bufPtr := udpproto.EncodeDataEnc2Pooled(cachedKS, cachedKS.CurID, routeName, clientAddr, localBuf[:n])
						pkt = outPacket{data: encoded, bufPtr: bufPtr}
					} else {
						pkt = outPacket{data: udpproto.EncodeData(routeName, clientAddr, localBuf[:n]), bufPtr: nil}
					}

					// Non-blocking send to writer
					select {
					case outQueue <- pkt:
						// Queued successfully
					default:
						// Writer overwhelmed - drop packet
						stats.RecordLoss(1)
						if pkt.bufPtr != nil {
							udpproto.PutOutputBuffer(pkt.bufPtr)
						}
					}
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
		}
		inJobs := make(chan inJob, 65536) // Increased from 16384 to 65536

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

					// Dispatch to worker - pass buffer ownership
					select {
					case inJobs <- inJob{data: buf, len: n, bufPtr: bufPtr}:
						// Dispatched successfully
					default:
						// Workers overwhelmed - drop packet
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
						routeName, clientAddr, payload, _, ok = udpproto.DecodeDataEnc2(cachedKS, pkt)
						if !ok {
							stats.RecordLoss(1)
							udpBufPool.Put(job.bufPtr)
							continue
						}
					} else {
						routeName, clientAddr, payload, ok = udpproto.DecodeData(pkt)
						if !ok {
							stats.RecordLoss(1)
							udpBufPool.Put(job.bufPtr)
							continue
						}
					}
					rt, ok := routesByName[routeName]
					if !ok || !routeHasUDP(rt.Proto) {
						stats.RecordLoss(1)
						log.Debugf(logging.CatUDP, "UDP packet dropped: unknown route=%s", routeName)
						udpBufPool.Put(job.bufPtr)
						continue
					}
					localTarget, ok := localTargetFromPublicAddr(rt.PublicAddr)
					if !ok {
						stats.RecordLoss(1)
						udpBufPool.Put(job.bufPtr)
						continue
					}
					s, ok := getOrCreate(routeName, clientAddr, localTarget)
					if !ok || s == nil {
						stats.RecordLoss(1)
						udpBufPool.Put(job.bufPtr)
						continue
					}
					if _, err := s.conn.Write(payload); err != nil {
						stats.RecordLoss(1)
					} else {
						stats.RecordReceive(len(payload))
					}
					udpBufPool.Put(job.bufPtr)
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

		close(outQueue)
		writerWg.Wait()

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

// runtimeNumCPU returns the number of CPUs, handling the case where runtime isn't imported
func runtimeNumCPU() int {
	return 8 // Default to 8 if we can't get the actual CPU count
}
