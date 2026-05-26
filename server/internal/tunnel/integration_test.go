package tunnel

import (
	"testing"
	"time"

	"hostit/shared/apitypes"
)

func TestDynamicRouteRegisterConfirmRemove(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     "40000-40100",
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
	}, nil)

	s.mu.Lock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "e2e-1", Name: "webapp", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", Source: "api",
	})
	if resp.Status != "active" {
		t.Fatalf("register: Status = %q, want active", resp.Status)
	}
	if resp.Name != "webapp" {
		t.Fatalf("register: Name = %q, want webapp", resp.Name)
	}
	if resp.PublicAddr == "" {
		t.Fatal("register: PublicAddr should not be empty")
	}

	ack := s.processRouteConfirmLocked(apitypes.RouteConfirm{
		RequestID: "e2e-1", Name: "webapp", Domain: "webapp.example.com",
	})
	if ack.Status != "active" {
		t.Fatalf("confirm: Status = %q, want active", ack.Status)
	}
	if ack.Domain != "webapp.example.com" {
		t.Fatalf("confirm: Domain = %q, want webapp.example.com", ack.Domain)
	}

	dr, ok := s.dynamicRoutes["webapp"]
	if !ok {
		t.Fatal("webapp not in dynamicRoutes after confirm")
	}
	if dr.Route.Domain != "webapp.example.com" {
		t.Fatalf("stored domain = %q, want webapp.example.com", dr.Route.Domain)
	}

	rmAck := s.processRouteRemoveLocked(apitypes.RouteRemove{Name: "webapp", Source: "api"})
	if !rmAck.OK {
		t.Fatalf("remove: OK = %v, want true", rmAck.OK)
	}

	_, exists := s.dynamicRoutes["webapp"]
	if exists {
		t.Fatal("webapp still in dynamicRoutes after removal")
	}

	s.mu.Unlock()
}

func TestDynamicRouteUpdateLocalAddr(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "40100-40200",
	}, nil)

	s.mu.Lock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "e2e-2", Name: "myapp", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 40100, Source: "api",
	})
	if resp.Status != "active" {
		t.Fatalf("register: Status = %q", resp.Status)
	}

	updateAck := s.processRouteUpdateLocked(apitypes.RouteUpdate{
		RequestID: "e2e-upd", Name: "myapp", LocalAddr: "127.0.0.1:4000",
	})
	if updateAck.Status != "updated" {
		t.Fatalf("update: Status = %q, want updated", updateAck.Status)
	}

	dr, ok := s.dynamicRoutes["myapp"]
	if !ok {
		t.Fatal("myapp not in dynamicRoutes")
	}
	if dr.Route.LocalAddr != "127.0.0.1:4000" {
		t.Fatalf("updated local addr = %q, want 127.0.0.1:4000", dr.Route.LocalAddr)
	}

	s.mu.Unlock()
}

func TestDynamicRouteUpdateNonExistent(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "40200-40300",
	}, nil)

	s.mu.Lock()
	defer s.mu.Unlock()

	ack := s.processRouteUpdateLocked(apitypes.RouteUpdate{
		RequestID: "e2e-nx", Name: "nonexistent", LocalAddr: "127.0.0.1:9999",
	})
	if ack.Status != "failed" {
		t.Fatalf("Status = %q, want failed", ack.Status)
	}
}

func TestDynamicRoutePortConflictBetweenDynamic(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "40300-40400",
	}, nil)

	s.mu.Lock()

	r1 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "e2e-pc1", Name: "app1", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 40300, Source: "api",
	})
	if r1.Status != "active" {
		t.Fatalf("app1: Status = %q", r1.Status)
	}

	r2 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "e2e-pc2", Name: "app2", Proto: "tcp",
		LocalAddr: "127.0.0.1:4000", PublicPort: 40300, Source: "api",
	})
	s.mu.Unlock()

	if r2.Status != "failed" {
		t.Fatalf("app2 should fail on port conflict, got Status = %q", r2.Status)
	}
}

func TestDynamicRouteMultipleProtos(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "40400-40500",
	}, nil)

	s.mu.Lock()

	for i, proto := range []string{"tcp", "udp", "both"} {
		name := "app-" + proto
		resp := s.processRouteRequestLocked(apitypes.RouteRequest{
			RequestID: "e2e-proto", Name: name, Proto: proto,
			LocalAddr: "127.0.0.1:3000", PublicPort: 40400 + i, Source: "api",
		})
		if resp.Status != "active" {
			t.Errorf("proto %s: Status = %q, want active", proto, resp.Status)
		}
	}

	s.mu.Unlock()
}

func TestRouteStats(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "40500-40600",
	}, nil)

	s.mu.Lock()
	s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "e2e-st", Name: "statapp", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 40500, Source: "api",
	})
	s.mu.Unlock()

	stats := s.RouteStats("statapp")
	if stats == nil {
		t.Fatal("RouteStats returned nil")
	}
	if stats.Name != "statapp" {
		t.Fatalf("Name = %q, want statapp", stats.Name)
	}
	if stats.Source != "dynamic" {
		t.Fatalf("Source = %q, want dynamic", stats.Source)
	}
	if stats.PublicAddr != ":40500" {
		t.Fatalf("PublicAddr = %q, want :40500", stats.PublicAddr)
	}

	allStats := s.AllRouteStats()
	found := false
	for _, st := range allStats {
		if st.Name == "statapp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("statapp not in AllRouteStats")
	}

	nilStats := s.RouteStats("nonexistent")
	if nilStats != nil {
		t.Fatal("RouteStats for nonexistent should return nil")
	}
}

func TestDynamicRouteAutoDomainWithConfirm(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     "40600-40700",
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
	}, nil)

	s.mu.Lock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "e2e-ad", Name: "mysite", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", Domain: "auto", Source: "api",
	})
	if resp.Status != "active" {
		t.Fatalf("Status = %q, want active (auto domain should resolve)", resp.Status)
	}
	if resp.Domain != "mysite.example.com" {
		t.Fatalf("Domain = %q, want mysite.example.com", resp.Domain)
	}

	s.mu.Unlock()
}

func TestEffectiveRoutesIncludesDynamic(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "40700-40800",
		Routes: []RouteConfig{
			{Name: "static-web", Proto: "tcp", PublicAddr: ":8080"},
		},
	}, nil)

	s.mu.Lock()
	s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "e2e-er", Name: "dynamic-api", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 40700, Source: "api",
	})

	routes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	s.mu.Unlock()

	names := make(map[string]bool)
	for _, rt := range routes {
		names[rt.Name] = true
	}
	if !names["static-web"] {
		t.Error("static-web missing from effectiveRoutes")
	}
	if !names["dynamic-api"] {
		t.Error("dynamic-api missing from effectiveRoutes")
	}
}

func TestBuildHelloIncludesDynamicRoutes(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "40800-40900",
	}, nil)

	s.mu.Lock()
	s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "e2e-hi", Name: "hello-route", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 40800, Source: "api",
	})

	helloRoutes := buildHelloRoutes(s.cfg, s.dynamicRoutes)
	s.mu.Unlock()

	if _, ok := helloRoutes["hello-route"]; !ok {
		t.Fatal("hello-route missing from buildHelloRoutes output")
	}
}

func TestDynamicRouteUpdatePortChange(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "40900-41000",
	}, nil)

	s.mu.Lock()

	s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "e2e-pu", Name: "portchange", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 40900, Source: "api",
	})

	if _, ok := s.publicTCP["portchange"]; !ok {
		t.Fatal("no TCP listener for portchange")
	}

	ack := s.processRouteUpdateLocked(apitypes.RouteUpdate{
		RequestID: "e2e-pu2", Name: "portchange", PublicPort: 40901,
	})
	if ack.Status != "updated" {
		t.Fatalf("update: Status = %q, want updated", ack.Status)
	}

	if _, ok := s.publicTCP["portchange"]; !ok {
		t.Fatal("no TCP listener for portchange after port update")
	}

	dr := s.dynamicRoutes["portchange"]
	if dr.Route.PublicAddr != ":40901" {
		t.Fatalf("PublicAddr = %q, want :40901", dr.Route.PublicAddr)
	}

	s.mu.Unlock()
}
