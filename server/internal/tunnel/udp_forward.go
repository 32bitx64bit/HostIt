package tunnel

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/logging"
	"hostit/shared/protocol"
)

func (s *Server) acceptAgentUDP() {
	defer s.wg.Done()
	defer s.udpDataConn.Close()

	buf := make([]byte, 65536)
	decryptBuf := make([]byte, 65536)
	aadBuf := make([]byte, 0, 512)
	var pkt protocol.Packet

	// Deduplicate accepted proofs before taking sessionsMu or running Ed25519
	// verification. Bookkeeping is bounded independently for each live identity.
	seenRegisters := newUDPRegisterReplayCache()
	var lastRegisterReplayPrune int64

	// Two-generation client-addr parse cache: the same client strings repeat
	// on every datagram of a flow, so parsing once per flow avoids the
	// per-packet netip.ParseAddrPort cost.
	const maxClientAddrCache = 10000 / 2
	clientAddrCur := make(map[string]netip.AddrPort)
	var clientAddrPrev map[string]netip.AddrPort

	for {
		n, addr, err := s.udpDataConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}

		err = protocol.UnmarshalUDPTo(buf[:n], &pkt)
		if err != nil {
			continue
		}

		if pkt.Type == protocol.TypeRegister {
			// A v3 peer must prove its identity, UDP session, and exact live control
			// generation before the observed source is adopted. Source-IP equality
			// is deliberately unnecessary for split-path/NAT deployments. The signed
			// nonce blocks token-only impersonation, and the replay cache prevents a
			// proof from moving the endpoint again after its first accepted use.
			nowT := time.Now()
			reg, ok := crypto.ParseBoundUDPRegister(s.cfg.Token, pkt.Payload, nowT, udpRegisterAuthWindow)
			if !ok {
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-register-reject", fmt.Sprintf("rejected malformed/unauthenticated bound UDP register from %s", addr))
				continue
			}
			if reg.AgentID == "" {
				reg.AgentID = protocol.DefaultAgentID
			}
			nowNano := nowT.UnixNano()
			if nowNano-lastRegisterReplayPrune >= int64(udpRegisterAuthWindow/2) {
				seenRegisters.prune(nowNano)
				lastRegisterReplayPrune = nowNano
			}
			if seen, full := seenRegisters.status(reg.AgentID, reg.ControlNonce, reg.Key, nowNano); seen || full {
				continue
			}

			s.sessionsMu.Lock()
			sess := s.sessions[reg.AgentID]
			if sess == nil {
				s.sessionsMu.Unlock()
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-register-nosession", fmt.Sprintf("rejected UDP register for agent %q from %s: no live control session", reg.AgentID, addr))
				continue
			}
			if sess.controlNonce != reg.ControlNonce || !reg.VerifyIdentity(sess.identityPublicKey) {
				s.sessionsMu.Unlock()
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-register-generation", fmt.Sprintf("rejected UDP register for agent %q from %s: identity/control generation mismatch", reg.AgentID, addr))
				continue
			}

			if !seenRegisters.record(reg.AgentID, reg.ControlNonce, reg.Key, reg.ValidUntil().UnixNano(), nowNano) {
				s.sessionsMu.Unlock()
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-register-rate-"+reg.AgentID, fmt.Sprintf("rejected excessive UDP registrations for agent %q from %s", reg.AgentID, addr))
				continue
			}

			s.udpAgentsMu.Lock()
			prev := s.loadUDPAgents()[reg.AgentID]
			if prev == nil {
				logging.Global().Infof(logging.CatUDP, "Agent %q UDP address registered: %s", reg.AgentID, addr.String())
			} else if prev.addr != addr {
				logging.Global().Infof(logging.CatUDP, "Agent %q UDP address updated: %s", reg.AgentID, addr.String())
			}
			s.updateUDPAgentAddrLocked(reg.AgentID, addr, reg.SessionID, reg.ControlNonce, nowNano)
			s.pruneUDPAgentsLocked(nowNano)
			s.udpAgentsMu.Unlock()
			s.sessionsMu.Unlock()
			continue
		}

		if pkt.Type == protocol.TypeData {
			routeName := pkt.Route
			clientID := pkt.Client

			// One route-cache load yields owner, enabled, and encryption.
			rc, rcOK := s.getRouteConfig(routeName)
			if !rcOK || !rc.enabled {
				continue
			}
			owner := rc.owner
			if owner == "" {
				owner = protocol.DefaultAgentID
			}
			// Accept tunneled data only from the route owner's registered address.
			st := s.loadUDPAgents()[owner]
			if st == nil || st.addr != addr {
				continue
			}
			// Active data refreshes liveness (throttled).
			now := time.Now().UnixNano()
			if now-st.lastSeen.Load() > int64(500*time.Millisecond) {
				st.lastSeen.Store(now)
			}

			pubConn, ok := s.loadPublicUDP()[routeName]
			if !ok {
				continue
			}

			payload := pkt.Payload
			if rc.isEncrypted {
				if st.crypto == nil {
					continue
				}
				aadBuf = crypto.AppendUDPDataAAD(aadBuf[:0], routeName, clientID)
				decrypted, err := st.crypto.dec.Open(decryptBuf, payload, aadBuf)
				if err != nil {
					s.udpDrops.Add(1)
					logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-open-"+routeName, fmt.Sprintf("dropping undecryptable UDP packet route=%s client=%s err=%v", routeName, clientID, err))
					continue
				}
				payload = decrypted
			}

			clientAddrPort, cached := clientAddrCur[clientID]
			if !cached {
				if clientAddrPort, cached = clientAddrPrev[clientID]; !cached {
					ap, err := netip.ParseAddrPort(clientID)
					if err != nil {
						continue
					}
					clientAddrPort = ap
				}
				if len(clientAddrCur) >= maxClientAddrCache {
					clientAddrPrev = clientAddrCur
					clientAddrCur = make(map[string]netip.AddrPort, 64)
				}
				clientAddrCur[clientID] = clientAddrPort
			}

			s.dash.addBytes(time.Now(), int64(len(payload)))
			written, err := pubConn.WriteToUDPAddrPort(payload, clientAddrPort)
			if err != nil {
				s.udpDrops.Add(1)
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-write-public-"+routeName, fmt.Sprintf("failed to write UDP payload to public client route=%s client=%s bytes=%d err=%v", routeName, clientID, len(payload), err))
				continue
			}
			if written != len(payload) {
				s.udpDrops.Add(1)
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-short-write-public-"+routeName, fmt.Sprintf("short UDP payload write to public client route=%s client=%s wrote=%d want=%d", routeName, clientID, written, len(payload)))
			}
		}
	}
}

func (s *Server) acceptPublicUDP(conn *net.UDPConn, routeName string) {
	defer s.wg.Done()
	defer conn.Close()

	buf := make([]byte, 65536)
	marshalBuf := make([]byte, protocol.MaxUDPDatagramSize)
	encryptBuf := make([]byte, protocol.MaxUDPDatagramSize)
	aadBuf := make([]byte, 0, 512)

	// Two-generation addr->string cache: when the current generation fills,
	// it becomes the previous one and live entries are promoted back on
	// access. Bounded without the churn of evicting random hot entries.
	const maxAddrStrCache = 10000 / 2
	addrStrCur := make(map[netip.AddrPort]string)
	var addrStrPrev map[netip.AddrPort]string
	for {
		n, addr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}

		clientStr, ok := addrStrCur[addr]
		if !ok {
			if clientStr, ok = addrStrPrev[addr]; !ok {
				clientStr = addr.String()
			}
			if len(addrStrCur) >= maxAddrStrCache {
				addrStrPrev = addrStrCur
				addrStrCur = make(map[netip.AddrPort]string, 64)
			}
			addrStrCur[addr] = clientStr
		}

		rc, rcOK := s.getRouteConfig(routeName)
		if !rcOK || !rc.enabled {
			continue
		}
		owner := rc.owner
		if owner == "" {
			owner = protocol.DefaultAgentID
		}
		st := s.loadUDPAgents()[owner]
		if st == nil || !st.addr.IsValid() {
			s.udpDrops.Add(1)
			continue
		}
		// Owner registration gone stale; acceptAgentUDP prunes it.
		if time.Since(time.Unix(0, st.lastSeen.Load())) > udpRegisterTimeout {
			s.udpDrops.Add(1)
			continue
		}
		s.dash.addBytes(time.Now(), int64(n))
		aadBuf = s.writeUDPToAgent(routeName, clientStr, owner, rc.epoch, st, buf[:n], marshalBuf, encryptBuf, aadBuf)
	}
}

func warnLargeTunneledUDPDatagram(direction, routeName, clientID string, frameLen int) {
	protocol.WarnLargeTunneledUDPDatagram(direction, routeName, clientID, frameLen, func(key, message string) {
		logging.Global().RateLimitedWarn(logging.CatUDP, key, message)
	})
}
