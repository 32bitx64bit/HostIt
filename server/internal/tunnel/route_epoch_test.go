package tunnel

import "testing"

func replaceServerTestRoutes(s *Server, routes []RouteConfig) {
	s.mu.Lock()
	s.cfg.Routes = routes
	s.updateRouteCacheLocked()
	s.mu.Unlock()
}

func serverTestRouteEpoch(t *testing.T, s *Server, name string) uint64 {
	t.Helper()
	route, ok := s.getRouteConfig(name)
	if !ok || route.epoch == 0 {
		t.Fatalf("route %q has no live epoch", name)
	}
	return route.epoch
}

func TestServerRouteEpochRetainedForIdenticalRebuild(t *testing.T) {
	route := RouteConfig{Name: "video", Proto: "udp", PublicAddr: ":47998", LocalAddr: "127.0.0.1:47998"}
	s := NewServer(ServerConfig{Routes: []RouteConfig{route}}, nil)
	before := serverTestRouteEpoch(t, s, route.Name)

	replaceServerTestRoutes(s, []RouteConfig{route})
	if after := serverTestRouteEpoch(t, s, route.Name); after != before {
		t.Fatalf("identical route rebuild changed epoch from %d to %d", before, after)
	}
}

func TestServerRouteEpochBumpsForChangeAndRecreation(t *testing.T) {
	route := RouteConfig{Name: "control", Proto: "udp", PublicAddr: ":47999", LocalAddr: "127.0.0.1:47999"}
	s := NewServer(ServerConfig{Routes: []RouteConfig{route}}, nil)
	initial := serverTestRouteEpoch(t, s, route.Name)

	changed := route
	changed.LocalAddr = "127.0.0.1:48001"
	replaceServerTestRoutes(s, []RouteConfig{changed})
	changedEpoch := serverTestRouteEpoch(t, s, route.Name)
	if changedEpoch == initial {
		t.Fatalf("changed route retained epoch %d", initial)
	}

	replaceServerTestRoutes(s, nil)
	if _, ok := s.getRouteConfig(route.Name); ok {
		t.Fatal("removed route remained in the route cache")
	}
	replaceServerTestRoutes(s, []RouteConfig{route})
	if recreated := serverTestRouteEpoch(t, s, route.Name); recreated == initial || recreated == changedEpoch {
		t.Fatalf("recreated route reused an old epoch: initial=%d changed=%d recreated=%d", initial, changedEpoch, recreated)
	}
}

func TestServerUnrelatedRouteDoesNotBumpEpoch(t *testing.T) {
	control := RouteConfig{Name: "control", Proto: "udp", PublicAddr: ":47999", LocalAddr: "127.0.0.1:47999"}
	s := NewServer(ServerConfig{Routes: []RouteConfig{control}}, nil)
	controlEpoch := serverTestRouteEpoch(t, s, control.Name)

	audio := RouteConfig{Name: "audio", Proto: "udp", PublicAddr: ":48000", LocalAddr: "127.0.0.1:48000"}
	replaceServerTestRoutes(s, []RouteConfig{control, audio})
	if afterAdd := serverTestRouteEpoch(t, s, control.Name); afterAdd != controlEpoch {
		t.Fatalf("adding an unrelated route changed control epoch from %d to %d", controlEpoch, afterAdd)
	}

	audio.LocalAddr = "127.0.0.1:48002"
	replaceServerTestRoutes(s, []RouteConfig{control, audio})
	if afterChange := serverTestRouteEpoch(t, s, control.Name); afterChange != controlEpoch {
		t.Fatalf("changing an unrelated route changed control epoch from %d to %d", controlEpoch, afterChange)
	}
}
