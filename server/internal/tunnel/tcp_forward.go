package tunnel

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/logging"
	"hostit/shared/netutil"
	"hostit/shared/protocol"
	"hostit/shared/relay"
)

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
		netutil.SetTCPKeepAlive(conn, tcpKeepAliveInterval)
		netutil.SetTCPNoDelay(conn)

		handshakeDL := time.Now().Add(handshakeDeadline)
		conn.SetDeadline(handshakeDL)
		clientNonce, serverNonce, err := crypto.AuthenticateServer(conn, s.cfg.Token)
		if err != nil {
			logging.Global().Errorf(logging.CatTCP, "data auth failed from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}
		conn.SetReadDeadline(handshakeDL)

		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			conn.Close()
			continue
		}
		routeBytes := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, routeBytes); err != nil {
			conn.Close()
			continue
		}

		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			conn.Close()
			continue
		}
		clientBytes := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, clientBytes); err != nil {
			conn.Close()
			continue
		}
		clientID := string(clientBytes)
		conn.SetReadDeadline(handshakeDL)

		routeName := string(routeBytes)
		if routeName == protocol.RouteMailOutboundTCP {
			target := string(clientBytes)
			s.dialMailOutboundTCP(conn, target)
			continue
		}

		// Pairing token is sent in the clear before optional tunnel encryption.
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			conn.Close()
			continue
		}
		pairBytes := make([]byte, lenBuf[0])
		if lenBuf[0] > 0 {
			if _, err := io.ReadFull(conn, pairBytes); err != nil {
				conn.Close()
				continue
			}
		}

		rc, _ := s.getRouteConfig(routeName)
		isEncrypted := rc.isEncrypted

		if isEncrypted {
			key := rc.derivedKey
			if key == nil {
				logging.Global().Errorf(logging.CatTCP, "failed to derive key for route %s: key is nil", routeName)
				conn.Close()
				continue
			}
			conn, err = crypto.WrapTCP(conn, key, clientNonce, serverNonce, false)
			if err != nil {
				logging.Global().Errorf(logging.CatTCP, "failed to wrap tcp for route %s: %v", routeName, err)
				conn.Close()
				continue
			}
		}

		pendingKey := makePendingTCPKey(routeName, clientID)
		s.mu.Lock()
		entry, ok := s.pendingTCP[pendingKey]
		if ok {
			delete(s.pendingTCP, pendingKey)
		}
		s.mu.Unlock()

		if !ok {
			logging.Global().RateLimitedWarn(logging.CatTCP, "data-unmatched-"+routeName, fmt.Sprintf("data handshake with no pending pairing route=%s client=%s from=%s", routeName, clientID, conn.RemoteAddr()))
			conn.Close()
			continue
		}
		if len(entry.pairToken) > 0 && subtle.ConstantTimeCompare(entry.pairToken, pairBytes) != 1 {
			logging.Global().RateLimitedWarn(logging.CatTCP, "data-pair-token-"+routeName, fmt.Sprintf("rejected data pairing with bad token route=%s client=%s from=%s", routeName, clientID, conn.RemoteAddr()))
			conn.Close()
			entry.cancel()
			continue
		}
		if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
			if entry.controlRemote != "" && !controlPeerIPMatches(entry.controlRemote, ap) {
				logging.Global().RateLimitedWarn(logging.CatTCP, "data-pair-ip-"+routeName, fmt.Sprintf("rejected data pairing from %s; control peer is %s route=%s client=%s", conn.RemoteAddr(), entry.controlRemote, routeName, clientID))
				conn.Close()
				entry.cancel()
				continue
			}
		}
		// SetDeadline above armed both read and write. Clearing only the
		// read side left a ~15s write deadline on domain keep-alive conns
		// returned by dialRouteTCP (public relays overwrite it via idle
		// timeout wrappers). Clear both before handing the conn off.
		_ = conn.SetDeadline(time.Time{})
		entry.deliver(conn)
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

		semVal, _ := s.connSemaphores.LoadOrStore(routeName, make(chan struct{}, s.maxConnsPerRoute))
		sem, ok := semVal.(chan struct{})
		if !ok {
			logging.Global().Errorf(logging.CatTCP, "invalid semaphore type for route=%s, rejecting", routeName)
			conn.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			logging.Global().Warnf(logging.CatTCP, "connection limit reached for route=%s, rejecting", routeName)
			conn.Close()
			continue
		}

		netutil.SetTCPKeepAlive(conn, tcpKeepAliveInterval)
		netutil.SetTCPNoDelay(conn)
		// Reap public peers that vanish without a clean shutdown quickly,
		// so the relay (and the agent's downstream session) is freed
		// before the relay idle timeout.
		netutil.TuneDeadPeerDetection(conn)
		clientID := s.nextClientID()
		logging.Global().Infof(logging.CatTCP, "New public TCP connection route=%s client=%s", routeName, clientID)

		rc, ok := s.getRouteConfig(routeName)
		enabled := ok && rc.enabled
		owner := rc.owner
		if owner == "" {
			owner = protocol.DefaultAgentID
		}
		session, sessionOK := s.sessionForAgent(owner)

		if !sessionOK || !enabled {
			<-sem
			if isEmailRoute(routeName) {
				logging.Global().Warnf(logging.CatTCP, "mail public connection rejected route=%s owner=%s agentConnected=%v enabled=%v", routeName, owner, sessionOK, enabled)
				writeMailRouteUnavailable(conn, routeName)
			}
			conn.Close()
			continue
		}

		entry := newPendingTCPPair(owner, session.remoteAddr)
		pendingKey := makePendingTCPKey(routeName, clientID)
		s.mu.Lock()
		s.pendingTCP[pendingKey] = entry
		s.mu.Unlock()

		reqPkt := &protocol.Packet{
			Type:    protocol.TypeConnect,
			Route:   routeName,
			Client:  clientID,
			Payload: entry.pairToken,
		}
		session.writeMu.Lock()
		writeErr := writeControl(session.conn, reqPkt, writeDeadlineStandard)
		session.writeMu.Unlock()
		if writeErr != nil {
			logging.Global().Errorf(logging.CatTCP, "failed to request agent connect route=%s client=%s: %v", routeName, clientID, writeErr)
			<-sem
			writeMailRouteUnavailable(conn, routeName)
			conn.Close()
			s.mu.Lock()
			delete(s.pendingTCP, pendingKey)
			s.mu.Unlock()
			entry.cancel()
			continue
		}

		go func(c net.Conn, clientID string, sem chan struct{}) {
			defer c.Close()
			defer func() { <-sem }()
			timer := time.NewTimer(s.cfg.PairTimeout)
			defer timer.Stop()
			select {
			case <-entry.done:
				logging.Global().Warnf(logging.CatTCP, "agent pairing aborted route=%s client=%s", routeName, clientID)
				writeMailRouteUnavailable(c, routeName)
				return
			case <-entry.ready:
				agentConn := entry.take()
				if agentConn == nil {
					logging.Global().Warnf(logging.CatTCP, "agent pairing missing backend route=%s client=%s", routeName, clientID)
					writeMailRouteUnavailable(c, routeName)
					return
				}
				logging.Global().Infof(logging.CatTCP, "paired public TCP route=%s client=%s", routeName, clientID)
				s.dash.addConn(time.Now())
				s.dash.incActive(routeName)
				defer s.dash.decActive(routeName)

				s.runCountedRelay(routeName, c, agentConn)

			case <-timer.C:
				// Race: delivery may have landed at the same moment the
				// timer fired. Use it instead of discarding a valid pair.
				agentConn := entry.take()
				if agentConn != nil {
					logging.Global().Infof(logging.CatTCP, "paired public TCP route=%s client=%s (race recovery)", routeName, clientID)
					s.dash.addConn(time.Now())
					s.dash.incActive(routeName)
					defer s.dash.decActive(routeName)

					s.runCountedRelay(routeName, c, agentConn)
					return
				}
				logging.Global().Warnf(logging.CatTCP, "pair timeout route=%s client=%s", routeName, clientID)
				s.mu.Lock()
				delete(s.pendingTCP, pendingKey)
				s.mu.Unlock()
				entry.cancel()
				writeMailRouteUnavailable(c, routeName)
			}
		}(conn, clientID, sem)
	}
}

// runCountedRelay wraps the public + agent leg in countingConns and runs
// the relay. Each Read accounts bytes directly in the dashboard.
func (s *Server) runCountedRelay(routeName string, publicConn, agentConn net.Conn) {
	pubCounter := &countingConn{Conn: publicConn, dash: s.dash}
	agtCounter := &countingConn{Conn: agentConn, dash: s.dash}
	relay.ProxyWithIdleTimeout(pubCounter, agtCounter, proxyIdleTimeout)
}
