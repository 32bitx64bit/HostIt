package tunnel

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"hostit/shared/protocol"
)

type blockingServerUDPWriter struct {
	firstOnce sync.Once
	started   chan struct{}
	release   chan struct{}
	writes    chan []byte

	mu        sync.Mutex
	active    int
	maxActive int
}

func newBlockingServerUDPWriter() *blockingServerUDPWriter {
	return &blockingServerUDPWriter{
		started: make(chan struct{}),
		release: make(chan struct{}),
		writes:  make(chan []byte, 32),
	}
}

func (w *blockingServerUDPWriter) SetWriteDeadline(time.Time) error { return nil }

func (w *blockingServerUDPWriter) WriteToUDPAddrPort(payload []byte, _ netip.AddrPort) (int, error) {
	w.mu.Lock()
	w.active++
	if w.active > w.maxActive {
		w.maxActive = w.active
	}
	w.mu.Unlock()

	w.firstOnce.Do(func() {
		close(w.started)
		<-w.release
	})
	w.writes <- append([]byte(nil), payload...)

	w.mu.Lock()
	w.active--
	w.mu.Unlock()
	return len(payload), nil
}

func nextServerUDPPacket(t *testing.T, writes <-chan []byte) protocol.Packet {
	t.Helper()
	select {
	case data := <-writes:
		pkt, err := protocol.UnmarshalUDP(data)
		if err != nil {
			t.Fatalf("unmarshal egress packet: %v", err)
		}
		return *pkt
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP egress write")
		return protocol.Packet{}
	}
}

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
			t.Fatalf("route %q has no active UDP egress epoch", name)
		}
		configs[name] = rc
	}
	return srv, configs
}

func liveAgentUDPState(port uint16) *agentUDPState {
	state := &agentUDPState{addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	state.lastSeen.Store(time.Now().UnixNano())
	return state
}

func TestServerUDPEgressFairlySchedulesRoutesWithOneWriter(t *testing.T) {
	srv, routes := newServerWithUDPRoutes(t, "video", "control")
	state := liveAgentUDPState(40001)
	srv.udpAgents.Store(&map[string]*agentUDPState{protocol.DefaultAgentID: state})

	writer := newBlockingServerUDPWriter()
	egress, err := newServerUDPEgress(srv, writer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go egress.run(ctx)

	if err := egress.enqueue("video", "client", protocol.DefaultAgentID, routes["video"].epoch, state, []byte("video-0")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first video write did not enter sink")
	}
	if err := egress.enqueue("video", "client", protocol.DefaultAgentID, routes["video"].epoch, state, []byte("video-1")); err != nil {
		t.Fatal(err)
	}
	if err := egress.enqueue("video", "client", protocol.DefaultAgentID, routes["video"].epoch, state, []byte("video-2")); err != nil {
		t.Fatal(err)
	}
	if err := egress.enqueue("control", "client", protocol.DefaultAgentID, routes["control"].epoch, state, []byte("input")); err != nil {
		t.Fatal(err)
	}
	close(writer.release)

	want := []struct {
		route   string
		payload string
	}{
		{"video", "video-0"},
		{"video", "video-1"},
		{"control", "input"},
		{"video", "video-2"},
	}
	for i, expected := range want {
		pkt := nextServerUDPPacket(t, writer.writes)
		if pkt.Route != expected.route || string(pkt.Payload) != expected.payload {
			t.Fatalf("wire packet %d = route %q payload %q, want route %q payload %q", i, pkt.Route, pkt.Payload, expected.route, expected.payload)
		}
	}
	writer.mu.Lock()
	maxActive := writer.maxActive
	writer.mu.Unlock()
	if maxActive != 1 {
		t.Fatalf("concurrent socket writers = %d, want exactly one", maxActive)
	}
}

func TestServerUDPEgressDropsQueuedStaleAgentState(t *testing.T) {
	srv, routes := newServerWithUDPRoutes(t, "video")
	state1 := liveAgentUDPState(40001)
	srv.udpAgents.Store(&map[string]*agentUDPState{protocol.DefaultAgentID: state1})

	writer := newBlockingServerUDPWriter()
	egress, err := newServerUDPEgress(srv, writer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go egress.run(ctx)

	epoch := routes["video"].epoch
	if err := egress.enqueue("video", "client", protocol.DefaultAgentID, epoch, state1, []byte("in-flight")); err != nil {
		t.Fatal(err)
	}
	<-writer.started
	if err := egress.enqueue("video", "client", protocol.DefaultAgentID, epoch, state1, []byte("stale-state")); err != nil {
		t.Fatal(err)
	}

	state2 := liveAgentUDPState(40002)
	srv.udpAgents.Store(&map[string]*agentUDPState{protocol.DefaultAgentID: state2})
	if err := egress.enqueue("video", "client", protocol.DefaultAgentID, epoch, state2, []byte("fresh-state")); err != nil {
		t.Fatal(err)
	}
	close(writer.release)

	if pkt := nextServerUDPPacket(t, writer.writes); string(pkt.Payload) != "in-flight" {
		t.Fatalf("first payload = %q, want in-flight", pkt.Payload)
	}
	if pkt := nextServerUDPPacket(t, writer.writes); string(pkt.Payload) != "fresh-state" {
		t.Fatalf("packet after stale state = %q, want fresh-state", pkt.Payload)
	}
	if srv.udpDrops.Load() == 0 {
		t.Fatal("stale queued agent state was not counted as a drop")
	}
}

func TestServerUDPEgressDropsQueuedStaleRouteEpoch(t *testing.T) {
	srv, routes := newServerWithUDPRoutes(t, "video")
	state := liveAgentUDPState(40001)
	srv.udpAgents.Store(&map[string]*agentUDPState{protocol.DefaultAgentID: state})

	writer := newBlockingServerUDPWriter()
	egress, err := newServerUDPEgress(srv, writer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go egress.run(ctx)

	oldRoute := routes["video"]
	if err := egress.enqueue("video", "client", protocol.DefaultAgentID, oldRoute.epoch, state, []byte("in-flight")); err != nil {
		t.Fatal(err)
	}
	<-writer.started
	if err := egress.enqueue("video", "client", protocol.DefaultAgentID, oldRoute.epoch, state, []byte("stale-epoch")); err != nil {
		t.Fatal(err)
	}

	newRoute := oldRoute
	newRoute.epoch++
	if newRoute.epoch == 0 {
		newRoute.epoch++
	}
	srv.routeCache.Store(map[string]routeConfig{"video": newRoute})
	if err := egress.enqueue("video", "client", protocol.DefaultAgentID, newRoute.epoch, state, []byte("fresh-epoch")); err != nil {
		t.Fatal(err)
	}
	close(writer.release)

	if pkt := nextServerUDPPacket(t, writer.writes); string(pkt.Payload) != "in-flight" {
		t.Fatalf("first payload = %q, want in-flight", pkt.Payload)
	}
	if pkt := nextServerUDPPacket(t, writer.writes); string(pkt.Payload) != "fresh-epoch" {
		t.Fatalf("packet after stale epoch = %q, want fresh-epoch", pkt.Payload)
	}
	if srv.udpDrops.Load() == 0 {
		t.Fatal("stale queued route epoch was not counted as a drop")
	}
}
