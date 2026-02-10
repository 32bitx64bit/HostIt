package agent

import (
	"context"
	"net"
	"sync"
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
		// Larger UDP buffers reduce drops/jitter for high-bitrate UDP workloads.
		_ = uc.SetReadBuffer(4 * 1024 * 1024)
		_ = uc.SetWriteBuffer(4 * 1024 * 1024)

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

		sessionsMu := sync.RWMutex{}
		sessions := map[string]map[string]*udpSession{} // route -> client -> session

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
			_ = lconn.SetReadBuffer(4 * 1024 * 1024)
			_ = lconn.SetWriteBuffer(4 * 1024 * 1024)
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
				for {
					// Use a long idle timeout; only reset after actual timeout, not every read.
					_ = lconn.SetReadDeadline(time.Now().Add(idle))
					n, err := lconn.Read(localBuf)
					if err != nil {
						break
					}
					stats.RecordSend(n)
					// Refresh KeySet every ~1000 packets to pick up rotations without per-packet RLock.
					pktCount++
					if pktCount >= 1000 {
						cachedKS = sec.Get()
						pktCount = 0
					}
					if cachedKS.Enabled() {
						_, _ = uc.Write(udpproto.EncodeDataEnc2ForKeyID(cachedKS, cachedKS.CurID, routeName, clientAddr, localBuf[:n]))
					} else {
						_, _ = uc.Write(udpproto.EncodeData(routeName, clientAddr, localBuf[:n]))
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

		readBufPtr := udpBufPool.Get().(*[]byte)
		readBuf := *readBufPtr
		readErr := func() error {
			defer udpBufPool.Put(readBufPtr)
			for {
				// No per-read deadline: the keepalive goroutine already re-registers
				// every 5 seconds, so the server always has our address. Removing
				// SetReadDeadline avoids 2 syscalls (time.Now + setsockopt) per packet.
				n, err := uc.Read(readBuf)
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						ks := sec.Get()
						if ks.Enabled() {
							_, _ = uc.Write(udpproto.EncodeRegEnc2(ks, token))
						} else {
							_, _ = uc.Write(udpproto.EncodeReg(token))
						}
						continue
					}
					return err
				}
				stats.RecordReceive(n)
				ks := sec.Get()
				var (
					routeName  string
					clientAddr string
					payload    []byte
					ok         bool
				)
				if ks.Enabled() {
					routeName, clientAddr, payload, _, ok = udpproto.DecodeDataEnc2(ks, readBuf[:n])
					if !ok {
						stats.RecordLoss(1)
						continue
					}
				} else {
					routeName, clientAddr, payload, ok = udpproto.DecodeData(readBuf[:n])
					if !ok {
						stats.RecordLoss(1)
						continue
					}
				}
				rt, ok := routesByName[routeName]
				if !ok || !routeHasUDP(rt.Proto) {
					stats.RecordLoss(1)
					log.Debugf(logging.CatUDP, "UDP packet dropped: unknown route=%s", routeName)
					continue
				}
				localTarget, ok := localTargetFromPublicAddr(rt.PublicAddr)
				if !ok {
					stats.RecordLoss(1)
					continue
				}
				s, ok := getOrCreate(routeName, clientAddr, localTarget)
				if !ok || s == nil {
					stats.RecordLoss(1)
					continue
				}
				_, _ = s.conn.Write(payload)
			}
		}()

		close(kaDone)
		_ = uc.Close()
		log.Info(logging.CatUDP, "UDP connection closed, reconnecting...")
		_ = readErr
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
