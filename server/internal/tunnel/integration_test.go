package tunnel

import (
	"fmt"
	"net"
	"testing"
	"time"

	"hostit/shared/apitypes"
)

func freeTCPPortForIntegrationTest(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func freeTCPPortsForIntegrationTest(t *testing.T, count int) []int {
	t.Helper()
	ports := make([]int, 0, count)
	seen := make(map[int]bool, count)
	for len(ports) < count {
		port := freeTCPPortForIntegrationTest(t)
		if seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	return ports
}

func singlePortRangeForIntegrationTest(port int) string {
	return fmt.Sprintf("%d-%d", port, port)
}

func TestDynamicRouteRegisterConfirmRemove(t *testing.T) {
	port := freeTCPPortForIntegrationTest(t)
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     singlePortRangeForIntegrationTest(port),
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
	}, nil)

	s.mu.Lock()

	resp := s.testProcessRouteRequest(apitypes.RouteRequest{
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
	port := freeTCPPortForIntegrationTest(t)
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: singlePortRangeForIntegrationTest(port),
	}, nil)

	s.mu.Lock()

	resp := s.testProcessRouteRequest(apitypes.RouteRequest{
		RequestID: "e2e-2", Name: "myapp", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: port, Source: "api",
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
	port := freeTCPPortForIntegrationTest(t)
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: singlePortRangeForIntegrationTest(port),
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
	port := freeTCPPortForIntegrationTest(t)
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: singlePortRangeForIntegrationTest(port),
	}, nil)

	s.mu.Lock()

	r1 := s.testProcessRouteRequest(apitypes.RouteRequest{
		RequestID: "e2e-pc1", Name: "app1", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: port, Source: "api",
	})
	if r1.Status != "active" {
		t.Fatalf("app1: Status = %q", r1.Status)
	}

	r2 := s.testProcessRouteRequest(apitypes.RouteRequest{
		RequestID: "e2e-pc2", Name: "app2", Proto: "tcp",
		LocalAddr: "127.0.0.1:4000", PublicPort: port, Source: "api",
	})
	s.mu.Unlock()

	if r2.Status != "failed" {
		t.Fatalf("app2 should fail on port conflict, got Status = %q", r2.Status)
	}
}

func TestDynamicRouteMultipleProtos(t *testing.T) {
	ports := freeTCPPortsForIntegrationTest(t, 3)
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: fmt.Sprintf("%d-%d", ports[0], ports[0]),
	}, nil)

	s.mu.Lock()

	for i, proto := range []string{"tcp", "udp", "both"} {
		name := "app-" + proto
		resp := s.testProcessRouteRequest(apitypes.RouteRequest{
			RequestID: "e2e-proto", Name: name, Proto: proto,
			LocalAddr: "127.0.0.1:3000", PublicPort: ports[i], Source: "api",
		})
		if resp.Status != "active" {
			t.Errorf("proto %s: Status = %q, want active", proto, resp.Status)
		}
	}

	s.mu.Unlock()
}

func TestRouteStats(t *testing.T) {
	port := freeTCPPortForIntegrationTest(t)
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: singlePortRangeForIntegrationTest(port),
	}, nil)

	s.mu.Lock()
	s.testProcessRouteRequest(apitypes.RouteRequest{
		RequestID: "e2e-st", Name: "statapp", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: port, Source: "api",
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
	wantPublicAddr := fmt.Sprintf(":%d", port)
	if stats.PublicAddr != wantPublicAddr {
		t.Fatalf("PublicAddr = %q, want %s", stats.PublicAddr, wantPublicAddr)
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
	port := freeTCPPortForIntegrationTest(t)
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     singlePortRangeForIntegrationTest(port),
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
	}, nil)

	s.mu.Lock()

	resp := s.testProcessRouteRequest(apitypes.RouteRequest{
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
	port := freeTCPPortForIntegrationTest(t)
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: singlePortRangeForIntegrationTest(port),
		Routes: []RouteConfig{
			{Name: "static-web", Proto: "tcp", PublicAddr: ":8080"},
		},
	}, nil)

	s.mu.Lock()
	s.testProcessRouteRequest(apitypes.RouteRequest{
		RequestID: "e2e-er", Name: "dynamic-api", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: port, Source: "api",
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
	port := freeTCPPortForIntegrationTest(t)
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: singlePortRangeForIntegrationTest(port),
	}, nil)

	s.mu.Lock()
	s.testProcessRouteRequest(apitypes.RouteRequest{
		RequestID: "e2e-hi", Name: "hello-route", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: port, Source: "api",
	})

	helloRoutes := buildHelloRoutes(s.cfg, s.dynamicRoutes)
	s.mu.Unlock()

	if _, ok := helloRoutes["hello-route"]; !ok {
		t.Fatal("hello-route missing from buildHelloRoutes output")
	}
}

func TestDynamicRouteUpdatePortChange(t *testing.T) {
	ports := freeTCPPortsForIntegrationTest(t, 2)
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: fmt.Sprintf("%d-%d", ports[0], ports[0]),
	}, nil)

	s.mu.Lock()

	s.testProcessRouteRequest(apitypes.RouteRequest{
		RequestID: "e2e-pu", Name: "portchange", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: ports[0], Source: "api",
	})

	if _, ok := s.publicTCP["portchange"]; !ok {
		t.Fatal("no TCP listener for portchange")
	}

	ack := s.processRouteUpdateLocked(apitypes.RouteUpdate{
		RequestID: "e2e-pu2", Name: "portchange", PublicPort: ports[1],
	})
	if ack.Status != "updated" {
		t.Fatalf("update: Status = %q, want updated", ack.Status)
	}

	if _, ok := s.publicTCP["portchange"]; !ok {
		t.Fatal("no TCP listener for portchange after port update")
	}

	dr := s.dynamicRoutes["portchange"]
	wantPublicAddr := fmt.Sprintf(":%d", ports[1])
	if dr.Route.PublicAddr != wantPublicAddr {
		t.Fatalf("PublicAddr = %q, want %s", dr.Route.PublicAddr, wantPublicAddr)
	}

	s.mu.Unlock()
}
