package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

func configureRouteUDPSocket(conn *net.UDPConn, routeName string) {
	result := netutil.SetUDPBuffers(conn, routeUDPReadBufferBytes, routeUDPWriteBufferBytes)
	if result.ReadErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request UDP read buffer route=%s bytes=%d: %v", routeName, result.ReadBytes, result.ReadErr)
	}
	if result.WriteErr != nil {
		logging.Global().Warnf(logging.CatUDP, "failed to request UDP write buffer route=%s bytes=%d: %v", routeName, result.WriteBytes, result.WriteErr)
	}
}

type serverUDPEgressMeta struct {
	client     string
	agentID    string
	state      *agentUDPState
	routeEpoch uint64
}

type serverUDPWriter interface {
	SetWriteDeadline(time.Time) error
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
}

// serverUDPEgress owns every write to the shared server->agent UDP socket.
// Public-route readers enqueue plaintext so encryption counters are allocated
// in the same order packets actually reach the socket.
type serverUDPEgress struct {
	server *Server
	conn   serverUDPWriter
	queue  *udpfair.Queue[serverUDPEgressMeta]
}

func newServerUDPEgress(server *Server, conn serverUDPWriter) (*serverUDPEgress, error) {
	queue, err := udpfair.NewQueue[serverUDPEgressMeta](udpfair.DefaultLimits())
	if err != nil {
		return nil, err
	}
	return &serverUDPEgress{server: server, conn: conn, queue: queue}, nil
}

func (e *serverUDPEgress) close() {
	if e != nil {
		e.queue.Close()
	}
}

func (e *serverUDPEgress) enqueue(route, client, agentID string, routeEpoch uint64, state *agentUDPState, payload []byte) error {
	if e == nil {
		return udpfair.ErrClosed
	}
	return e.queue.EnqueueRoute(route, payload, serverUDPEgressMeta{
		client: client, agentID: agentID, state: state, routeEpoch: routeEpoch,
	})
}

func (e *serverUDPEgress) run(ctx context.Context) {
	marshalBuf := make([]byte, protocol.MaxUDPDatagramSize)
	encryptBuf := make([]byte, protocol.MaxUDPDatagramSize)
	aadBuf := make([]byte, 0, 512)
	var writeDeadlineSet time.Time

	for {
		item, err := e.queue.Dequeue(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, udpfair.ErrClosed) {
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-egress-dequeue", fmt.Sprintf("UDP egress queue stopped: %v", err))
			}
			return
		}

		func() {
			defer item.Release()
			if item.System {
				e.server.udpDrops.Add(1)
				return
			}
			route := item.Route
			rc, ok := e.server.getRouteConfig(route)
			currentOwner := rc.owner
			if currentOwner == "" {
				currentOwner = protocol.DefaultAgentID
			}
			if !ok || !rc.enabled || currentOwner != item.Meta.agentID || rc.epoch != item.Meta.routeEpoch {
				e.server.udpDrops.Add(1)
				return
			}
			state := e.server.loadUDPAgents()[item.Meta.agentID]
			if state == nil || state != item.Meta.state || !state.addr.IsValid() || time.Since(time.Unix(0, state.lastSeen.Load())) > udpRegisterTimeout {
				e.server.udpDrops.Add(1)
				return
			}

			payload := item.Payload
			if rc.isEncrypted {
				if state.crypto == nil {
					e.server.udpDrops.Add(1)
					return
				}
				aadBuf = crypto.AppendUDPDataAAD(aadBuf[:0], route, item.Meta.client)
				payload, err = state.crypto.enc.Seal(encryptBuf, payload, aadBuf)
				if err != nil {
					e.server.udpDrops.Add(1)
					logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-seal-"+route, fmt.Sprintf("failed to encrypt UDP packet route=%s client=%s: %v", route, item.Meta.client, err))
					return
				}
			}

			pkt := protocol.Packet{Type: protocol.TypeData, Route: route, Client: item.Meta.client, Payload: payload}
			data, err := protocol.MarshalUDP(&pkt, marshalBuf)
			if err != nil {
				e.server.udpDrops.Add(1)
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-egress-marshal-"+route, fmt.Sprintf("failed to marshal UDP packet route=%s client=%s payload=%d err=%v", route, item.Meta.client, len(payload), err))
				return
			}
			warnLargeTunneledUDPDatagram("server-to-agent", route, item.Meta.client, len(data))

			now := time.Now()
			if now.Sub(writeDeadlineSet) >= sharedUDPWriteDeadlineRefresh {
				if err := e.conn.SetWriteDeadline(now.Add(sharedUDPWriteTimeout)); err != nil {
					logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-write-deadline", fmt.Sprintf("failed to bound shared UDP write: %v", err))
				}
				writeDeadlineSet = now
			}
			n, err := e.conn.WriteToUDPAddrPort(data, state.addr)
			if err != nil {
				e.server.udpDrops.Add(1)
				if ctx.Err() == nil {
					logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-write-agent-"+route, fmt.Sprintf("failed to write queued UDP packet route=%s client=%s bytes=%d err=%v", route, item.Meta.client, len(data), err))
				}
				return
			}
			if n != len(data) {
				e.server.udpDrops.Add(1)
				logging.Global().RateLimitedWarn(logging.CatUDP, "server-udp-short-write-agent-"+route, fmt.Sprintf("short queued UDP write route=%s client=%s wrote=%d want=%d", route, item.Meta.client, n, len(data)))
			}
		}()
	}
}
