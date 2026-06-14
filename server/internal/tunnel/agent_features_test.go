package tunnel

import "testing"

func TestDomainEnabledForAgent(t *testing.T) {
	cfg := ServerConfig{DomainDisabledAgents: []string{"laptop-mc"}}
	if !cfg.DomainEnabledForAgent("main-pc") {
		t.Error("unlisted agent should have domain enabled")
	}
	if cfg.DomainEnabledForAgent("laptop-mc") {
		t.Error("listed agent should have domain disabled")
	}
	if !cfg.DomainEnabledForAgent("") {
		t.Error("default agent should have domain enabled")
	}
}

func TestAgentFeatureToggles(t *testing.T) {
	srv := NewServer(ServerConfig{
		ControlAddr:          "127.0.0.1:0",
		DataAddr:             "127.0.0.1:0",
		Token:                "t",
		DisableTLS:           true,
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		Routes:               []RouteConfig{{Name: "web", Proto: "tcp", PublicAddr: ":8080", Agent: "main-pc"}},
	}, nil)
	srv.updateRouteCache()

	if !srv.domainEnabledForRoute("web") {
		t.Fatal("domain should be enabled by default")
	}
	srv.SetAgentDomainEnabled("main-pc", false)
	if srv.domainEnabledForRoute("web") {
		t.Fatal("domain should be disabled after toggling main-pc off")
	}
	srv.SetAgentDomainEnabled("main-pc", true)
	if !srv.domainEnabledForRoute("web") {
		t.Fatal("domain should be re-enabled")
	}

	srv.SetEmailAgent("main-pc")
	var st *AgentStatus
	for _, a := range srv.agentStatuses() {
		if a.ID == "main-pc" {
			a := a
			st = &a
		}
	}
	if st == nil {
		t.Fatal("main-pc missing from agent statuses")
	}
	if !st.EmailAgent {
		t.Error("main-pc should be the email agent")
	}
	if !st.DomainEnabled {
		t.Error("main-pc domain should be enabled")
	}
}
