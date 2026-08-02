package agent

import (
	"fmt"
	"net"
	"sync"

	"hostit/shared/crypto"
	"hostit/shared/logging"
	"hostit/shared/netutil"
	"hostit/shared/protocol"
)

const (
	// Kernel buffers are a small shock absorber only. UDP is send-and-forget:
	// if the socket cannot accept a datagram, drop it and move on.
	sharedUDPReadBufferBytes  = netutil.SharedUDPReadBufferBytes
	sharedUDPWriteBufferBytes = netutil.SharedUDPWriteBufferBytes
	routeUDPReadBufferBytes   = netutil.RouteUDPReadBufferBytes
	routeUDPWriteBufferBytes  = netutil.RouteUDPWriteBufferBytes
)

func configureLocalUDPSocket(conn *net.UDPConn, routeName string) {
	result := netutil.SetUDPBuffers(conn, routeUDPReadBufferBytes, routeUDPWriteBufferBytes)
	if result.ReadErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request local UDP read buffer route=%s bytes=%d: %v", routeName, result.ReadBytes, result.ReadErr)
	}
	if result.WriteErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request local UDP write buffer route=%s bytes=%d: %v", routeName, result.WriteBytes, result.WriteErr)
	}
}

type agentUDPWriter interface {
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

// agentUDPEgress writes agent->server UDP immediately. mu only protects the
// reusable scratch buffers; there is no application queue.
type agentUDPEgress struct {
	agent      *Agent
	conn       agentUDPWriter
	serverAddr *net.UDPAddr

	mu         sync.Mutex
	marshalBuf []byte
	encryptBuf []byte
	aadBuf     []byte
}

func newAgentUDPEgress(agent *Agent, conn agentUDPWriter, serverAddr *net.UDPAddr) *agentUDPEgress {
	return &agentUDPEgress{
		agent:      agent,
		conn:       conn,
		serverAddr: serverAddr,
		marshalBuf: make([]byte, protocol.MaxUDPDatagramSize),
		encryptBuf: make([]byte, protocol.MaxUDPDatagramSize),
		aadBuf:     make([]byte, 0, 512),
	}
}

func (e *agentUDPEgress) sendRegister(controlNonce crypto.UDPControlNonce, payload []byte) {
	if e == nil {
		return
	}
	e.agent.mu.RLock()
	current := e.agent.udpControlNonce
	ready := e.agent.udpRegisterReady
	e.agent.mu.RUnlock()
	if !ready || current != controlNonce {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.writePacketLocked(protocol.Packet{Type: protocol.TypeRegister, Payload: payload})
}

func (e *agentUDPEgress) sendData(route, client string, routeEpoch uint64, payload []byte) {
	if e == nil {
		return
	}
	rt, sessionCrypto, epoch, ok := e.agent.currentUDPEgressRoute(route)
	if !ok || epoch != routeEpoch {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	out := payload
	if rt.Encrypted {
		if sessionCrypto == nil {
			return
		}
		e.aadBuf = crypto.AppendUDPDataAAD(e.aadBuf[:0], route, client)
		encrypted, err := sessionCrypto.Enc.Seal(e.encryptBuf, out, e.aadBuf)
		if err != nil {
			logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-seal-"+route, fmt.Sprintf("failed to encrypt UDP response route=%s client=%s: %v", route, client, err))
			return
		}
		out = encrypted
	}
	e.writePacketLocked(protocol.Packet{Type: protocol.TypeData, Route: route, Client: client, Payload: out})
}

func (e *agentUDPEgress) writePacketLocked(pkt protocol.Packet) {
	data, err := protocol.MarshalUDP(&pkt, e.marshalBuf)
	if err != nil {
		logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-marshal", fmt.Sprintf("failed to marshal UDP packet route=%s client=%s payload=%d err=%v", pkt.Route, pkt.Client, len(pkt.Payload), err))
		return
	}
	warnLargeTunneledUDPDatagram("agent-to-server", pkt.Route, pkt.Client, len(data))
	n, err := e.conn.WriteToUDP(data, e.serverAddr)
	if err != nil {
		logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-write-server", fmt.Sprintf("failed to write UDP packet route=%s client=%s bytes=%d err=%v", pkt.Route, pkt.Client, len(data), err))
		return
	}
	if n != len(data) {
		logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-short-write-server", fmt.Sprintf("short UDP write route=%s client=%s wrote=%d want=%d", pkt.Route, pkt.Client, n, len(data)))
	}
}
