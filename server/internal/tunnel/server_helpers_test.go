package tunnel

import (
	"net"
	"testing"
	"time"

	"hostit/shared/emailcfg"
)

func TestBuildHelloPayloadIncludesRoutesAndEmailConfig(t *testing.T) {
	encrypted := true
	cfg := ServerConfig{
		EncryptionAlgorithm: "aes-256",
		Email: emailcfg.Config{
			Enabled:         true,
			Domain:          "example.com",
			MailHost:        "mail.example.com",
			InboundSMTP:     true,
			InboundSMTPAddr: "0.0.0.0:25",
			Accounts:        []emailcfg.Account{{Username: "admin", PasswordSet: true, Enabled: true}},
		},
		Routes: []RouteConfig{{
			Name:       "web",
			Proto:      "both",
			PublicAddr: ":443",
			LocalAddr:  "127.0.0.1:3000",
			Encrypted:  &encrypted,
		}},
	}

	payload := buildHelloPayload(cfg)
	rt, ok := payload.Routes["web"]
	if !ok {
		t.Fatalf("buildHelloPayload() missing route: %#v", payload.Routes)
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
	if !payload.Email.Enabled {
		t.Fatal("Email.Enabled = false, want true")
	}
	if payload.Email.EffectiveMailHost() != "mail.example.com" {
		t.Fatalf("EffectiveMailHost = %q, want %q", payload.Email.EffectiveMailHost(), "mail.example.com")
	}
	if len(payload.Email.Accounts) != 1 || payload.Email.Accounts[0].Username != "admin" {
		t.Fatalf("Email accounts = %#v, want one admin account", payload.Email.Accounts)
	}
	mailRT, ok := payload.Routes[internalEmailInboundRouteName]
	if !ok {
		t.Fatalf("buildHelloPayload() missing synthesized mail route: %#v", payload.Routes)
	}
	if mailRT.PublicAddr != emailInboundPublicAddr {
		t.Fatalf("mail route PublicAddr = %q, want %q", mailRT.PublicAddr, emailInboundPublicAddr)
	}
	if mailRT.LocalAddr != "127.0.0.1:25" {
		t.Fatalf("mail route LocalAddr = %q, want %q", mailRT.LocalAddr, "127.0.0.1:25")
	}
	submissionRT, ok := payload.Routes[internalEmailSubmissionRouteName]
	if !ok {
		t.Fatalf("buildHelloPayload() missing synthesized submission route: %#v", payload.Routes)
	}
	if submissionRT.PublicAddr != ":587" || submissionRT.LocalAddr != "127.0.0.1:1587" {
		t.Fatalf("submission route = %#v, want public :587 local 127.0.0.1:1587", submissionRT)
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

func TestGetRouteEnabled_UsesEffectiveRoutes(t *testing.T) {
	t.Parallel()

	srv := NewServer(ServerConfig{
		ControlAddr: ":7000",
		DataAddr:    ":7001",
		Token:       "testtoken",
		DisableTLS:  true,
		Email: emailcfg.Config{
			Enabled:         true,
			Domain:          "example.com",
			MailHost:        "mail.example.com",
			InboundSMTP:     true,
			InboundSMTPAddr: "0.0.0.0:25",
		},
	})

	if !srv.GetRouteEnabled(internalEmailInboundRouteName) {
		t.Fatalf("GetRouteEnabled(%q) = false, want true", internalEmailInboundRouteName)
	}
}
