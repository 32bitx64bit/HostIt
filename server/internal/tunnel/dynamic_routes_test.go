package tunnel

import (
	"testing"
	"time"

	"hostit/shared/apitypes"
)

func newTestServerForDynamic() *Server {
	return NewServer(ServerConfig{
		ControlAddr:              "127.0.0.1:0",
		DataAddr:                 "127.0.0.1:0",
		Token:                    "testtoken",
		DisableTLS:               true,
		PairTimeout:              3 * time.Second,
		DynamicPortRange:         "30000-30100",
		MaxDynamicRoutesPerAgent: 10,
	}, nil)
}

func TestProcessRouteRequestLocked_BasicRegistration(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID:  "req-1",
		Name:       "myapp",
		Proto:      "tcp",
		LocalAddr:  "127.0.0.1:3000",
		PublicPort: 30000,
		Source:     "api",
	})

	if resp.Status != "active" {
		t.Fatalf("Status = %q, want %q", resp.Status, "active")
	}
	if resp.Name != "myapp" {
		t.Fatalf("Name = %q, want %q", resp.Name, "myapp")
	}
	if resp.PublicAddr != ":30000" {
		t.Fatalf("PublicAddr = %q, want %q", resp.PublicAddr, ":30000")
	}
	if resp.Proto != "tcp" {
		t.Fatalf("Proto = %q, want %q", resp.Proto, "tcp")
	}

	dr, ok := s.dynamicRoutes["myapp"]
	if !ok {
		t.Fatal("dynamic route not stored")
	}
	if dr.Route.Name != "myapp" {
		t.Fatalf("stored route Name = %q, want %q", dr.Route.Name, "myapp")
	}
	if dr.Source != "api" {
		t.Fatalf("stored route Source = %q, want %q", dr.Source, "api")
	}
}

func TestProcessRouteRequestLocked_EmptyName(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-2",
		Name:      "",
		Proto:     "tcp",
	})

	if resp.Status != "failed" {
		t.Fatalf("Status = %q, want %q", resp.Status, "failed")
	}
	if resp.Error != "name is required" {
		t.Fatalf("Error = %q, want %q", resp.Error, "name is required")
	}
}

func TestProcessRouteRequestLocked_InvalidName(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-3",
		Name:      "bad name!",
		Proto:     "tcp",
	})

	if resp.Status != "failed" {
		t.Fatalf("Status = %q, want %q", resp.Status, "failed")
	}
}

func TestProcessRouteRequestLocked_InvalidProto(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-4",
		Name:      "app",
		Proto:     "icmp",
	})

	if resp.Status != "failed" {
		t.Fatalf("Status = %q, want %q", resp.Status, "failed")
	}
	if resp.Error != "invalid proto" {
		t.Fatalf("Error = %q, want %q", resp.Error, "invalid proto")
	}
}

func TestProcessRouteRequestLocked_StaticNameConflict(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		Routes:           []RouteConfig{{Name: "existing", Proto: "tcp", PublicAddr: ":443"}},
		DynamicPortRange: "30010-30100",
	}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID:  "req-5",
		Name:       "existing",
		Proto:      "tcp",
		LocalAddr:  "127.0.0.1:3000",
		PublicPort: 30010,
		Source:     "api",
	})

	if resp.Status != "failed" {
		t.Fatalf("Status = %q, want %q", resp.Status, "failed")
	}
}

func TestProcessRouteRequestLocked_DuplicateDynamicName(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()

	resp1 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-1", Name: "myapp", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 30001, Source: "api",
	})
	if resp1.Status != "active" {
		t.Fatalf("first registration: Status = %q, want active", resp1.Status)
	}

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-2", Name: "myapp", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 30002, Source: "api",
	})
	s.mu.Unlock()

	if resp.Status != "failed" {
		t.Fatalf("Status = %q, want %q for duplicate dynamic name", resp.Status, "failed")
	}
}

func TestProcessRouteRequestLocked_PortConflict(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		Routes:           []RouteConfig{{Name: "web", Proto: "tcp", PublicAddr: ":8080"}},
		DynamicPortRange: "30020-30100",
	}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID:  "req-6",
		Name:       "conflict",
		Proto:      "tcp",
		LocalAddr:  "127.0.0.1:3000",
		PublicPort: 8080,
		Source:     "api",
	})

	if resp.Status != "failed" {
		t.Fatalf("Status = %q, want %q", resp.Status, "failed")
	}
}

func TestProcessRouteRequestLocked_AutoPortAssignment(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "30800-30900",
	}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-7",
		Name:      "auto-port",
		Proto:     "tcp",
		LocalAddr: "127.0.0.1:3000",
		Source:    "api",
	})

	if resp.Status != "active" {
		t.Fatalf("Status = %q, want %q", resp.Status, "active")
	}
	if resp.PublicAddr == "" {
		t.Fatal("PublicAddr should not be empty with auto port")
	}
	if resp.PublicAddr != ":30800" {
		t.Fatalf("PublicAddr = %q, want first available port :30800", resp.PublicAddr)
	}
}

func TestProcessRouteRequestLocked_MaxDynamicRoutes(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:              "127.0.0.1:0",
		DataAddr:                 "127.0.0.1:0",
		Token:                    "testtoken",
		DisableTLS:               true,
		PairTimeout:              3 * time.Second,
		DynamicPortRange:         "30030-30100",
		MaxDynamicRoutesPerAgent: 2,
	}, nil)
	s.mu.Lock()

	r1 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "r1", Name: "app1", Proto: "tcp",
		LocalAddr: "127.0.0.1:1", PublicPort: 30030, Source: "api",
	})
	if r1.Status != "active" {
		t.Fatalf("app1: Status = %q, want active", r1.Status)
	}
	r2 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "r2", Name: "app2", Proto: "tcp",
		LocalAddr: "127.0.0.1:2", PublicPort: 30031, Source: "api",
	})
	if r2.Status != "active" {
		t.Fatalf("app2: Status = %q, want active", r2.Status)
	}

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "r3", Name: "app3", Proto: "tcp",
		LocalAddr: "127.0.0.1:3", PublicPort: 30032, Source: "api",
	})
	s.mu.Unlock()

	if resp.Status != "failed" {
		t.Fatalf("Status = %q, want %q", resp.Status, "failed")
	}
}

func TestProcessRouteRequestLocked_DomainQuery(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     "30040-30100",
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
	}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-dq",
		Name:      "myapp",
		Proto:     "tcp",
		LocalAddr: "127.0.0.1:3000",
		Domain:    "_query",
		Source:    "api",
	})

	if resp.Status != "pending_domain" {
		t.Fatalf("Status = %q, want %q", resp.Status, "pending_domain")
	}
}

func TestProcessRouteRequestLocked_UDPWithDomainRejected(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     "30050-30100",
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
	}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID:  "req-udp-domain",
		Name:       "udp-app",
		Proto:      "udp",
		LocalAddr:  "127.0.0.1:3000",
		PublicPort: 30050,
		Domain:     "udp-app.example.com",
		Source:     "api",
	})

	if resp.Status != "failed" {
		t.Fatalf("Status = %q, want %q", resp.Status, "failed")
	}
}

func TestProcessRouteRequestLocked_ReservedNameRejected(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID:  "req-reserved",
		Name:       "system",
		Proto:      "tcp",
		LocalAddr:  "127.0.0.1:3000",
		PublicPort: 30060,
		Source:     "api",
	})

	if resp.Status != "failed" {
		t.Fatalf("Status = %q, want %q for reserved name", resp.Status, "failed")
	}
}

func TestProcessRouteRequestLocked_ValidProtos(t *testing.T) {
	for i, proto := range []string{"tcp", "udp", "both"} {
		t.Run(proto, func(t *testing.T) {
			s := newTestServerForDynamic()
			s.mu.Lock()
			defer s.mu.Unlock()

			resp := s.processRouteRequestLocked(apitypes.RouteRequest{
				RequestID:  "req-proto",
				Name:       "app-" + proto,
				Proto:      proto,
				LocalAddr:  "127.0.0.1:3000",
				PublicPort: 30070 + i,
				Source:     "api",
			})

			if resp.Status == "failed" && resp.Error == "invalid proto" {
				t.Fatalf("proto %q should be valid", proto)
			}
		})
	}
}

func TestProcessRouteConfirmLocked_BasicConfirm(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     "30100-30200",
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
	}, nil)
	s.mu.Lock()

	r1 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-c1", Name: "app", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 30100, Source: "api",
	})
	if r1.Status != "active" {
		t.Fatalf("register: Status = %q, want active", r1.Status)
	}

	ack := s.processRouteConfirmLocked(apitypes.RouteConfirm{
		RequestID: "req-c1",
		Name:      "app",
		Domain:    "app.example.com",
	})
	s.mu.Unlock()

	if ack.Status != "active" {
		t.Fatalf("Status = %q, want %q", ack.Status, "active")
	}
	if ack.Domain != "app.example.com" {
		t.Fatalf("Domain = %q, want %q", ack.Domain, "app.example.com")
	}
	if ack.Name != "app" {
		t.Fatalf("Name = %q, want %q", ack.Name, "app")
	}
}

func TestProcessRouteConfirmLocked_RouteNotFound(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()
	defer s.mu.Unlock()

	ack := s.processRouteConfirmLocked(apitypes.RouteConfirm{
		RequestID: "req-c2",
		Name:      "nonexistent",
		Domain:    "nonexistent.example.com",
	})

	if ack.Status != "failed" {
		t.Fatalf("Status = %q, want %q", ack.Status, "failed")
	}
}

func TestProcessRouteConfirmLocked_DomainConflict(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     "30200-30300",
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
		Routes: []RouteConfig{
			{
				Name: "existing", Proto: "tcp", PublicAddr: ":443",
				Domain: "taken.example.com", DomainEnabled: boolPtr(true),
			},
		},
	}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()

	r1 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-c3", Name: "newapp", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 30200, Source: "api",
	})
	if r1.Status != "active" {
		t.Fatalf("register: Status = %q, want active", r1.Status)
	}

	ack := s.processRouteConfirmLocked(apitypes.RouteConfirm{
		RequestID: "req-c3",
		Name:      "newapp",
		Domain:    "taken.example.com",
	})

	if ack.Status != "failed" {
		t.Fatalf("Status = %q, want %q for domain conflict", ack.Status, "failed")
	}
}

func TestProcessRouteConfirmLocked_InvalidDomain(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()

	r1 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-c4", Name: "app2", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 30300, Source: "api",
	})
	if r1.Status != "active" {
		t.Fatalf("register: Status = %q, want active", r1.Status)
	}

	ack := s.processRouteConfirmLocked(apitypes.RouteConfirm{
		RequestID: "req-c4",
		Name:      "app2",
		Domain:    "bad domain!",
	})
	s.mu.Unlock()

	if ack.Status != "failed" {
		t.Fatalf("Status = %q, want %q for invalid domain", ack.Status, "failed")
	}
}

func TestProcessRouteRemoveLocked_BasicRemoval(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "30400-30500",
	}, nil)
	s.mu.Lock()

	r1 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-rm1", Name: "removeme", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 30400, Source: "api",
	})
	if r1.Status != "active" {
		t.Fatalf("register: Status = %q, want active", r1.Status)
	}

	ack := s.processRouteRemoveLocked(apitypes.RouteRemove{
		Name: "removeme", Source: "api",
	})
	s.mu.Unlock()

	if !ack.OK {
		t.Fatalf("OK = %v, want true", ack.OK)
	}
	if ack.Name != "removeme" {
		t.Fatalf("Name = %q, want %q", ack.Name, "removeme")
	}

	s.mu.RLock()
	_, exists := s.dynamicRoutes["removeme"]
	s.mu.RUnlock()
	if exists {
		t.Fatal("dynamic route should be removed")
	}
}

func TestProcessRouteRemoveLocked_NotFound(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()
	defer s.mu.Unlock()

	ack := s.processRouteRemoveLocked(apitypes.RouteRemove{
		Name: "nonexistent", Source: "api",
	})

	if ack.OK {
		t.Fatal("OK = true for nonexistent route, want false")
	}
	if ack.Error != "dynamic route not found" {
		t.Fatalf("Error = %q, want %q", ack.Error, "dynamic route not found")
	}
}

func TestProcessRouteRemoveLocked_CleanupDerivedKeys(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "30500-30600",
	}, nil)
	s.mu.Lock()

	r1 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-rk", Name: "encrypted-app", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 30500,
		Encrypted: true, Source: "api",
	})
	if r1.Status != "active" {
		t.Fatalf("register: Status = %q, want active", r1.Status)
	}

	s.processRouteRemoveLocked(apitypes.RouteRemove{
		Name: "encrypted-app", Source: "api",
	})
	s.mu.Unlock()

	s.mu.RLock()
	_, keyExists := s.derivedKeys["encrypted-app"]
	s.mu.RUnlock()

	if keyExists {
		t.Error("derived key should be cleaned up after route removal")
	}
}

func TestAssignPortLocked_Basic(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()
	defer s.mu.Unlock()

	allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	port := s.assignPortLocked(allRoutes)

	if port != 30000 {
		t.Fatalf("first available port = %d, want 30000", port)
	}
}

func TestAssignPortLocked_SkipsUsedPorts(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		Routes:           []RouteConfig{{Name: "web", Proto: "tcp", PublicAddr: ":30000"}},
		DynamicPortRange: "30000-30100",
	}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()

	allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	port := s.assignPortLocked(allRoutes)

	if port != 30001 {
		t.Fatalf("first available port = %d, want 30001 (30000 is used)", port)
	}
}

func TestAssignPortLocked_Exhaustion(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:      "127.0.0.1:0",
		DataAddr:         "127.0.0.1:0",
		Token:            "testtoken",
		DisableTLS:       true,
		PairTimeout:      3 * time.Second,
		DynamicPortRange: "30000-30001",
	}, nil)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.dynamicRoutes["a"] = dynamicRouteEntry{
		Route: RouteConfig{Name: "a", Proto: "tcp", PublicAddr: ":30000"},
	}
	s.dynamicRoutes["b"] = dynamicRouteEntry{
		Route: RouteConfig{Name: "b", Proto: "tcp", PublicAddr: ":30001"},
	}

	allRoutes := effectiveRoutes(s.cfg, s.dynamicRoutes)
	port := s.assignPortLocked(allRoutes)

	if port != 0 {
		t.Fatalf("port = %d, want 0 when all ports exhausted", port)
	}
}

func TestBuildDomainOptionsLocked_NoDomainManager(t *testing.T) {
	s := newTestServerForDynamic()
	s.mu.Lock()
	defer s.mu.Unlock()

	opts := s.buildDomainOptionsLocked()
	if opts != nil {
		t.Fatalf("expected nil when domain manager disabled, got %v", opts)
	}
}

func TestBuildDomainOptionsLocked_WithDynamicRoutes(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     "30600-30700",
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
	}, nil)
	s.mu.Lock()

	r1 := s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-do1", Name: "webapp", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 30600, Source: "api",
	})
	if r1.Status != "active" {
		t.Fatalf("register: Status = %q, want active", r1.Status)
	}

	opts := s.buildDomainOptionsLocked()
	s.mu.Unlock()

	if len(opts) == 0 {
		t.Fatal("expected at least one domain option")
	}

	found := false
	for _, opt := range opts {
		if opt.Host == "webapp.example.com" {
			found = true
			if !opt.Available {
				t.Fatalf("webapp.example.com should be available, got UsedBy=%q Reason=%q", opt.UsedBy, opt.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("expected domain option webapp.example.com, got %v", opts)
	}
}

func TestBuildDomainOptionsLocked_UsedDomain(t *testing.T) {
	s := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          3 * time.Second,
		DynamicPortRange:     "30700-30800",
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DomainHTTPSAddr:      "127.0.0.1:443",
		Routes: []RouteConfig{
			{
				Name: "existing", Proto: "tcp", PublicAddr: ":443",
				Domain: "taken.example.com", DomainEnabled: boolPtr(true),
			},
		},
	}, nil)
	s.mu.Lock()

	s.processRouteRequestLocked(apitypes.RouteRequest{
		RequestID: "req-do2", Name: "taken", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 30700, Source: "api",
	})

	opts := s.buildDomainOptionsLocked()
	s.mu.Unlock()

	for _, opt := range opts {
		if opt.Host == "taken.example.com" {
			if opt.Available {
				t.Fatal("taken.example.com should not be available")
			}
			if opt.UsedBy == "" {
				t.Fatal("UsedBy should be set for taken domain")
			}
		}
	}
}
