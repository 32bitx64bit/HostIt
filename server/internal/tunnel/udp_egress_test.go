package tunnel

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"hostit/shared/protocol"
)

func newServerWithUDPRoutes(t *testing.T, names ...string) (*Server, map[string]routeConfig) {
	t.Helper()
	routes := make([]RouteConfig, 0, len(names))
	for _, name := range names {
		routes = append(routes, RouteConfig{Name: name, Proto: "udp"})
	}
	srv := NewServer(ServerConfig{Routes: routes}, nil)
	configs := make(map[string]routeConfig, len(names))
	for _, name := range names {
		rc, ok := srv.getRouteConfig(name)
		if !ok || rc.epoch == 0 {
			t.Fatalf("route %q has no active UDP epoch", name)
		}
		configs[name] = rc
	}
	return srv, configs
}

func liveAgentUDPState(addr netip.AddrPort) *agentUDPState {
	state := &agentUDPState{addr: addr}
	state.lastSeen.Store(time.Now().UnixNano())
	return state
}

func TestWriteUDPToAgentSendsImmediately(t *testing.T) {
	srv, routes := newServerWithUDPRoutes(t, "control")

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	agentConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer agentConn.Close()

	srv.udpDataConn = serverConn
	state := liveAgentUDPState(agentConn.LocalAddr().(*net.UDPAddr).AddrPort())
	srv.udpAgents.Store(&map[string]*agentUDPState{protocol.DefaultAgentID: state})

	marshalBuf := make([]byte, protocol.MaxUDPDatagramSize)
	encryptBuf := make([]byte, protocol.MaxUDPDatagramSize)
	aadBuf := make([]byte, 0, 512)
	_ = srv.writeUDPToAgent("control", "client", protocol.DefaultAgentID, routes["control"].epoch, state, []byte("input"), marshalBuf, encryptBuf, aadBuf)

	_ = agentConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := agentConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("agent read: %v", err)
	}
	pkt, err := protocol.UnmarshalUDP(buf[:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pkt.Route != "control" || string(pkt.Payload) != "input" {
		t.Fatalf("packet = route %q payload %q, want control/input", pkt.Route, pkt.Payload)
	}
}

func TestWriteUDPToAgentDropsStaleAgentState(t *testing.T) {
	srv, routes := newServerWithUDPRoutes(t, "video")

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	agentConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer agentConn.Close()

	srv.udpDataConn = serverConn
	state1 := liveAgentUDPState(agentConn.LocalAddr().(*net.UDPAddr).AddrPort())
	state2 := liveAgentUDPState(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 40002))
	srv.udpAgents.Store(&map[string]*agentUDPState{protocol.DefaultAgentID: state2})

	marshalBuf := make([]byte, protocol.MaxUDPDatagramSize)
	encryptBuf := make([]byte, protocol.MaxUDPDatagramSize)
	aadBuf := make([]byte, 0, 512)
	_ = srv.writeUDPToAgent("video", "client", protocol.DefaultAgentID, routes["video"].epoch, state1, []byte("stale"), marshalBuf, encryptBuf, aadBuf)

	_ = agentConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 65536)
	if _, _, err := agentConn.ReadFromUDP(buf); err == nil {
		t.Fatal("stale agent state was written")
	}
	if srv.udpDrops.Load() == 0 {
		t.Fatal("stale agent state was not counted as a drop")
	}
}
