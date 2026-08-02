package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/logging"
	"hostit/shared/netutil"
	"hostit/shared/protocol"
	"hostit/shared/udpfair"
)

const (
	// UDP congestion should become loss quickly instead of letting one route
	// hold every other route behind a blocked socket write.
	sharedUDPWriteTimeout         = 2 * time.Millisecond
	sharedUDPWriteDeadlineRefresh = time.Millisecond
	// Keep the kernel FIFO small enough that route-fair application scheduling
	// sees fresh traffic promptly. A large socket queue would hide stale
	// datagrams after they can no longer be fairly interleaved.
	sharedUDPReadBufferBytes  = 512 * 1024
	sharedUDPWriteBufferBytes = 64 * 1024
	routeUDPReadBufferBytes   = 256 * 1024
	routeUDPWriteBufferBytes  = 128 * 1024
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

type agentUDPEgressMeta struct {
	client       string
	routeEpoch   uint64
	controlNonce crypto.UDPControlNonce
}

type agentUDPWriter interface {
	SetWriteDeadline(time.Time) error
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
}

// agentUDPEgress owns every write to the shared agent->server UDP socket.
// Producers enqueue plaintext; the owner selects priority, verifies current
// route metadata, then encrypts immediately before the ordered socket write.
type agentUDPEgress struct {
	agent      *Agent
	conn       agentUDPWriter
	serverAddr *net.UDPAddr
	queue      *udpfair.Queue[agentUDPEgressMeta]
}

func newAgentUDPEgress(agent *Agent, conn agentUDPWriter, serverAddr *net.UDPAddr) (*agentUDPEgress, error) {
	queue, err := udpfair.NewQueue[agentUDPEgressMeta](udpfair.DefaultLimits())
	if err != nil {
		return nil, err
	}
	return &agentUDPEgress{agent: agent, conn: conn, serverAddr: serverAddr, queue: queue}, nil
}

func (e *agentUDPEgress) close() {
	if e != nil {
		e.queue.Close()
	}
}

func (e *agentUDPEgress) enqueueRegister(controlNonce crypto.UDPControlNonce, payload []byte) error {
	if e == nil {
		return udpfair.ErrClosed
	}
	return e.queue.EnqueueSystem(payload, agentUDPEgressMeta{controlNonce: controlNonce})
}

func (e *agentUDPEgress) enqueueData(route, client string, routeEpoch uint64, payload []byte) error {
	if e == nil {
		return udpfair.ErrClosed
	}
	return e.queue.EnqueueRoute(route, payload, agentUDPEgressMeta{
		client:     client,
		routeEpoch: routeEpoch,
	})
}

func (e *agentUDPEgress) run(ctx context.Context) {
	marshalBuf := make([]byte, protocol.MaxUDPDatagramSize)
	encryptBuf := make([]byte, protocol.MaxUDPDatagramSize)
	aadBuf := make([]byte, 0, 512)
	var pkt protocol.Packet
	var writeDeadlineSet time.Time

	for {
		item, err := e.queue.Dequeue(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, udpfair.ErrClosed) {
				logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-egress-dequeue", fmt.Sprintf("UDP egress queue stopped: %v", err))
			}
			return
		}

		func() {
			defer item.Release()
			payload := item.Payload
			if item.System {
				e.agent.mu.RLock()
				current := e.agent.udpControlNonce
				ready := e.agent.udpRegisterReady
				e.agent.mu.RUnlock()
				if !ready || current != item.Meta.controlNonce {
					return
				}
				pkt = protocol.Packet{Type: protocol.TypeRegister, Payload: payload}
			} else {
				route := item.Route
				rt, sessionCrypto, epoch, ok := e.agent.currentUDPEgressRoute(route)
				if !ok || epoch != item.Meta.routeEpoch {
					return
				}
				if rt.Encrypted {
					if sessionCrypto == nil {
						return
					}
					aadBuf = crypto.AppendUDPDataAAD(aadBuf[:0], route, item.Meta.client)
					payload, err = sessionCrypto.Enc.Seal(encryptBuf, payload, aadBuf)
					if err != nil {
						logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-seal-"+route, fmt.Sprintf("failed to encrypt UDP response route=%s client=%s: %v", route, item.Meta.client, err))
						return
					}
				}
				pkt = protocol.Packet{Type: protocol.TypeData, Route: route, Client: item.Meta.client, Payload: payload}
			}

			data, err := protocol.MarshalUDP(&pkt, marshalBuf)
			if err != nil {
				logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-egress-marshal", fmt.Sprintf("failed to marshal UDP egress packet route=%s client=%s payload=%d err=%v", pkt.Route, pkt.Client, len(payload), err))
				return
			}
			warnLargeTunneledUDPDatagram("agent-to-server", pkt.Route, pkt.Client, len(data))

			now := time.Now()
			if now.Sub(writeDeadlineSet) >= sharedUDPWriteDeadlineRefresh {
				if err := e.conn.SetWriteDeadline(now.Add(sharedUDPWriteTimeout)); err != nil {
					logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-write-deadline", fmt.Sprintf("failed to bound shared UDP write: %v", err))
				}
				writeDeadlineSet = now
			}
			n, err := e.conn.WriteToUDP(data, e.serverAddr)
			if err != nil {
				if ctx.Err() == nil {
					logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-write-server", fmt.Sprintf("failed to write queued UDP packet route=%s client=%s bytes=%d err=%v", pkt.Route, pkt.Client, len(data), err))
				}
				return
			}
			if n != len(data) {
				logging.Global().RateLimitedWarn(logging.CatUDP, "agent-udp-short-write-server", fmt.Sprintf("short queued UDP write route=%s client=%s wrote=%d want=%d", pkt.Route, pkt.Client, n, len(data)))
			}
		}()
	}
}
