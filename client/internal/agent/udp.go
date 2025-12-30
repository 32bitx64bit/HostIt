package agent

import (
	"context"
	"net"
	"sync"
	"time"

	"hostit/client/internal/udpproto"
)

type udpSession struct {
	conn   *net.UDPConn
	route  string
	client string
	close  sync.Once
}

func runUDP(ctx context.Context, dataAddr string, token string, sec *udpSecurityState, routesByName map[string]RemoteRoute) {
	const idle = 2 * time.Minute
	const keepaliveEvery = 5 * time.Second

	for {
		if ctx.Err() != nil {
			return
		}

		c, err := net.Dial("udp", dataAddr)
		if err != nil {
			t := time.NewTimer(1 * time.Second)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			continue
		}

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

		sessionsMu := sync.Mutex{}
		sessions := map[string]map[string]*udpSession{} // route -> client -> session

		getOrCreate := func(routeName, clientAddr, localTarget string) (*udpSession, bool) {
			sessionsMu.Lock()
			defer sessionsMu.Unlock()
			m := sessions[routeName]
			if m == nil {
				m = map[string]*udpSession{}
				sessions[routeName] = m
			}
			if s := m[clientAddr]; s != nil {
				return s, true
			}

			raddr, err := net.ResolveUDPAddr("udp", localTarget)
			if err != nil {
				return nil, false
			}
			lc := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
			lconn, err := net.DialUDP("udp", lc, raddr)
			if err != nil {
				return nil, false
			}
			_ = lconn.SetReadBuffer(4 * 1024 * 1024)
			_ = lconn.SetWriteBuffer(4 * 1024 * 1024)
			s := &udpSession{conn: lconn, route: routeName, client: clientAddr}
			m[clientAddr] = s

			go func() {
				buf := make([]byte, 64*1024)
				for {
					_ = lconn.SetReadDeadline(time.Now().Add(idle))
					n, err := lconn.Read(buf)
					if err != nil {
						break
					}
					ks := sec.Get()
					if ks.Enabled() {
						_, _ = uc.Write(udpproto.EncodeDataEnc2ForKeyID(ks, ks.CurID, routeName, clientAddr, buf[:n]))
					} else {
						_, _ = uc.Write(udpproto.EncodeData(routeName, clientAddr, buf[:n]))
					}
				}

				s.close.Do(func() {
					_ = lconn.Close()
				})
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

		buf := make([]byte, 64*1024)
		readErr := func() error {
			for {
				_ = uc.SetReadDeadline(time.Now().Add(30 * time.Second))
				n, err := uc.Read(buf)
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
				ks := sec.Get()
				routeName, clientAddr, payload, _, ok := udpproto.DecodeDataEnc2(ks, buf[:n])
				if !ok {
					routeName, clientAddr, payload, ok = udpproto.DecodeData(buf[:n])
					if !ok {
						continue
					}
				}
				rt, ok := routesByName[routeName]
				if !ok || !routeHasUDP(rt.Proto) {
					continue
				}
				localTarget, ok := localTargetFromPublicAddr(rt.PublicAddr)
				if !ok {
					continue
				}
				s, ok := getOrCreate(routeName, clientAddr, localTarget)
				if !ok || s == nil {
					continue
				}
				_, _ = s.conn.Write(payload)
			}
		}()

		close(kaDone)
		_ = uc.Close()
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
