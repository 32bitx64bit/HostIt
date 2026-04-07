package tunnel

import (
	"net"
	"testing"
	"time"
)

func TestBuildHelloRoutesIncludesLocalAddrAndAlgorithm(t *testing.T) {
	encrypted := true
	cfg := ServerConfig{
		EncryptionAlgorithm: "aes-256",
		Routes: []RouteConfig{{
			Name:       "web",
			Proto:      "both",
			PublicAddr: ":443",
			LocalAddr:  "127.0.0.1:3000",
			Encrypted:  &encrypted,
		}},
	}

	routes := buildHelloRoutes(cfg)
	rt, ok := routes["web"]
	if !ok {
		t.Fatalf("buildHelloRoutes() missing route: %#v", routes)
	}
	if rt.LocalAddr != "127.0.0.1:3000" {
		t.Fatalf("LocalAddr = %q, want %q", rt.LocalAddr, "127.0.0.1:3000")
	}
	if rt.Algorithm != "aes-256" {
		t.Fatalf("Algorithm = %q, want %q", rt.Algorithm, "aes-256")
	}
	if !rt.Encrypted {
		t.Fatal("Encrypted = false, want true")
	}
}

func TestServerDashboardIncludesRuntimeStats(t *testing.T) {
	srv := NewServer(ServerConfig{
		ControlAddr: ":7000",
		DataAddr:    ":7001",
		DisableTLS:  true,
		Routes: []RouteConfig{{
			Name:       "web",
			Proto:      "tcp",
			PublicAddr: ":443",
			LocalAddr:  "127.0.0.1:3000",
		}},
	})

	srv.mu.Lock()
	srv.pendingTCP[makePendingTCPKey("web", "client-1")] = make(chan net.Conn)
	srv.lastAgentConnectAt = time.Unix(100, 0)
	srv.lastAgentDisconnectAt = time.Unix(200, 0)
	srv.mu.Unlock()

	srv.sessionsMu.Lock()
	srv.sessions["agent-1"] = &agentSession{}
	srv.sessionsMu.Unlock()

	srv.domainProxyCache.Store("web", struct{}{})

	snap := srv.Dashboard(time.Now())
	if snap.Runtime == nil {
		t.Fatal("Dashboard().Runtime = nil")
	}
	if snap.Runtime.PendingTCP != 1 {
		t.Fatalf("PendingTCP = %d, want 1", snap.Runtime.PendingTCP)
	}
	if snap.Runtime.AgentSessions != 1 {
		t.Fatalf("AgentSessions = %d, want 1", snap.Runtime.AgentSessions)
	}
	if snap.Runtime.ManagedProxyRoutes != 1 {
		t.Fatalf("ManagedProxyRoutes = %d, want 1", snap.Runtime.ManagedProxyRoutes)
	}
	if snap.Runtime.RouteCacheEntries != 1 {
		t.Fatalf("RouteCacheEntries = %d, want 1", snap.Runtime.RouteCacheEntries)
	}
	if snap.Runtime.LastAgentConnectUnix != 100 {
		t.Fatalf("LastAgentConnectUnix = %d, want 100", snap.Runtime.LastAgentConnectUnix)
	}
	if snap.Runtime.LastAgentDisconnectUnix != 200 {
		t.Fatalf("LastAgentDisconnectUnix = %d, want 200", snap.Runtime.LastAgentDisconnectUnix)
	}
}
