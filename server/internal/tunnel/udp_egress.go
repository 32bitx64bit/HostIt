package tunnel

import (
	"fmt"
	"net"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/logging"
	"hostit/shared/netutil"
	"hostit/shared/protocol"
)

const (
	// Kernel buffers are a small shock absorber only. UDP is send-and-forget:
	// if the socket cannot accept a datagram, drop it and move on.
	sharedUDPReadBufferBytes  = 256 * 1024
	sharedUDPWriteBufferBytes = 256 * 1024
	routeUDPReadBufferBytes   = 128 * 1024
	routeUDPWriteBufferBytes  = 128 * 1024
)

func configureRouteUDPSocket(conn *net.UDPConn, routeName string) {
	result := netutil.SetUDPBuffers(conn, routeUDPReadBufferBytes, routeUDPWriteBufferBytes)
	if result.ReadErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request UDP read buffer route=%s bytes=%d: %v", routeName, result.ReadBytes, result.ReadErr)
	}
	if result.WriteErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request UDP write buffer route=%s bytes=%d: %v", routeName, result.WriteBytes, result.WriteErr)
	}
}

// writeUDPToAgent encrypts (when required) and writes one datagram toward the
// agent. Callers own payload for the duration of the call. Failures are drops.
func (s *Server) writeUDPToAgent(route, client, agentID string, routeEpoch uint64, state *agentUDPState, payload, marshalBuf, encryptBuf, aadBuf []byte) []byte {
	rc, ok := s.getRouteConfig(route)
	currentOwner := rc.owner
	if currentOwner == "" {
		currentOwner = protocol.DefaultAgentID
	}
	if !ok || !rc.enabled || currentOwner != agentID || rc.epoch != routeEpoch {
		s.udpDrops.Add(1)
		return aadBuf
	}
	live := s.loadUDPAgents()[agentID]
	if live == nil || live != state || !state.addr.IsValid() || time.Since(time.Unix(0, state.lastSeen.Load())) > udpRegisterTimeout {
		s.udpDrops.Add(1)
		return aadBuf
	}

	out := payload
	if rc.isEncrypted {
		if state.crypto == nil {
			s.udpDrops.Add(1)
			return aadBuf
		}
		aadBuf = crypto.AppendUDPDataAAD(aadBuf[:0], route, client)
		encrypted, err := state.crypto.enc.Seal(encryptBuf, out, aadBuf)
		if err != nil {
			s.udpDrops.Add(1)
			logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-seal-"+route, fmt.Sprintf("failed to encrypt UDP packet route=%s client=%s: %v", route, client, err))
			return aadBuf
		}
		out = encrypted
	}

	pkt := protocol.Packet{Type: protocol.TypeData, Route: route, Client: client, Payload: out}
	data, err := protocol.MarshalUDP(&pkt, marshalBuf)
	if err != nil {
		s.udpDrops.Add(1)
		logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-marshal-"+route, fmt.Sprintf("failed to marshal UDP packet route=%s client=%s payload=%d err=%v", route, client, len(out), err))
		return aadBuf
	}
	warnLargeTunneledUDPDatagram("server-to-agent", route, client, len(data))

	n, err := s.udpDataConn.WriteToUDPAddrPort(data, state.addr)
	if err != nil {
		s.udpDrops.Add(1)
		logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-write-agent-"+route, fmt.Sprintf("failed to write UDP packet route=%s client=%s bytes=%d err=%v", route, client, len(data), err))
		return aadBuf
	}
	if n != len(data) {
		s.udpDrops.Add(1)
		logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-short-write-agent-"+route, fmt.Sprintf("short UDP write route=%s client=%s wrote=%d want=%d", route, client, n, len(data)))
	}
	return aadBuf
}
