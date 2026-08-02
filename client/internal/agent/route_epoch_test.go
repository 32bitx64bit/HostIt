package agent

import (
	"sync"
	"testing"
	"time"
)

type trackedAgentUDPSessionConn struct {
	closed bool
}

func (c *trackedAgentUDPSessionConn) Read([]byte) (int, error)         { return 0, nil }
func (c *trackedAgentUDPSessionConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *trackedAgentUDPSessionConn) SetReadDeadline(time.Time) error  { return nil }
func (c *trackedAgentUDPSessionConn) SetWriteDeadline(time.Time) error { return nil }
func (c *trackedAgentUDPSessionConn) Close() error {
	c.closed = true
	return nil
}

func replaceAgentTestRoutes(a *Agent, routes map[string]RemoteRoute) {
	a.mu.Lock()
	a.replaceRoutesLocked(routes)
	a.routeCacheGen.Add(1)
	a.mu.Unlock()
}

func agentTestRouteEpoch(t *testing.T, a *Agent, name string) uint64 {
	t.Helper()
	_, _, epoch, ok := a.currentUDPEgressRoute(name)
	if !ok || epoch == 0 {
		t.Fatalf("route %q has no live epoch", name)
	}
	return epoch
}

func TestAgentRouteEpochRetainedForIdenticalRoute(t *testing.T) {
	route := RemoteRoute{
		Name:       "video",
		Proto:      "udp",
		PublicAddr: ":47998",
		LocalAddr:  "127.0.0.1:47998",
		Encrypted:  true,
		Algorithm:  "aes-256",
		DerivedKey: []byte("same-key-material"),
	}
	a := NewAgent(Config{Routes: map[string]RemoteRoute{route.Name: route}})
	before := agentTestRouteEpoch(t, a, route.Name)

	identical := route
	identical.DerivedKey = append([]byte(nil), route.DerivedKey...)
	replaceAgentTestRoutes(a, map[string]RemoteRoute{identical.Name: identical})

	if after := agentTestRouteEpoch(t, a, route.Name); after != before {
		t.Fatalf("identical route epoch changed from %d to %d", before, after)
	}
}

func TestAgentRouteEpochBumpsForChangeAndRecreation(t *testing.T) {
	route := RemoteRoute{Name: "control", Proto: "udp", PublicAddr: ":47999", LocalAddr: "127.0.0.1:47999"}
	a := NewAgent(Config{Routes: map[string]RemoteRoute{route.Name: route}})
	initial := agentTestRouteEpoch(t, a, route.Name)

	changed := route
	changed.LocalAddr = "127.0.0.1:48001"
	replaceAgentTestRoutes(a, map[string]RemoteRoute{changed.Name: changed})
	changedEpoch := agentTestRouteEpoch(t, a, route.Name)
	if changedEpoch == initial {
		t.Fatalf("changed route retained epoch %d", initial)
	}

	replaceAgentTestRoutes(a, map[string]RemoteRoute{})
	if _, _, epoch, ok := a.currentUDPEgressRoute(route.Name); ok || epoch != 0 {
		t.Fatalf("removed route remained live: ok=%t epoch=%d", ok, epoch)
	}
	replaceAgentTestRoutes(a, map[string]RemoteRoute{route.Name: route})
	if recreated := agentTestRouteEpoch(t, a, route.Name); recreated == initial || recreated == changedEpoch {
		t.Fatalf("recreated route reused an old epoch: initial=%d changed=%d recreated=%d", initial, changedEpoch, recreated)
	}
}

func TestAgentUnrelatedRouteDoesNotBumpEpoch(t *testing.T) {
	control := RemoteRoute{Name: "control", Proto: "udp", PublicAddr: ":47999", LocalAddr: "127.0.0.1:47999"}
	a := NewAgent(Config{Routes: map[string]RemoteRoute{control.Name: control}})
	controlEpoch := agentTestRouteEpoch(t, a, control.Name)

	audio := RemoteRoute{Name: "audio", Proto: "udp", PublicAddr: ":48000", LocalAddr: "127.0.0.1:48000"}
	replaceAgentTestRoutes(a, map[string]RemoteRoute{control.Name: control, audio.Name: audio})
	if afterAdd := agentTestRouteEpoch(t, a, control.Name); afterAdd != controlEpoch {
		t.Fatalf("adding an unrelated route changed control epoch from %d to %d", controlEpoch, afterAdd)
	}

	audio.LocalAddr = "127.0.0.1:48002"
	replaceAgentTestRoutes(a, map[string]RemoteRoute{control.Name: control, audio.Name: audio})
	if afterChange := agentTestRouteEpoch(t, a, control.Name); afterChange != controlEpoch {
		t.Fatalf("changing an unrelated route changed control epoch from %d to %d", controlEpoch, afterChange)
	}
}

func TestAgentUDPSessionIsRetiredAcrossRouteEpoch(t *testing.T) {
	var sessions sync.Map
	key := struct{ route, client string }{"control", "client"}
	oldConn := &trackedAgentUDPSessionConn{}
	old := &agentUDPSession{conn: oldConn, routeEpoch: 1}
	sessions.Store(key, old)

	if got, ok := loadAgentUDPSessionForEpoch(&sessions, key, 2); ok || got != nil {
		t.Fatalf("stale session was reused: ok=%t session=%p", ok, got)
	}
	if !oldConn.closed {
		t.Fatal("stale session connection was not closed")
	}
	if _, ok := sessions.Load(key); ok {
		t.Fatal("stale session remained published")
	}

	freshConn := &trackedAgentUDPSessionConn{}
	fresh := &agentUDPSession{conn: freshConn, routeEpoch: 2}
	sessions.Store(key, fresh)
	got, ok := loadAgentUDPSessionForEpoch(&sessions, key, 2)
	if !ok || got != fresh {
		t.Fatalf("current session not reused: ok=%t got=%p want=%p", ok, got, fresh)
	}
	if freshConn.closed {
		t.Fatal("current session connection was closed")
	}
}
