package main

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"hostit/server/internal/tunnel"
)

func TestStatsPollerRecoversAfterDashboardRestart(t *testing.T) {
	for _, want := range []string{"function scheduleReload()", "async function fetchJSON(url)", "AbortController", "Accept':'application/json'", "Syncing"} {
		if !strings.Contains(serverStatsHTML, want) {
			t.Fatalf("server stats template missing restart recovery fragment %q", want)
		}
	}
	if !strings.Contains(serverStatsHTML, "ok==='warn'") {
		t.Fatal("server stats template should support a warning pill state while status is resyncing")
	}
}

func TestDashboardTemplateRendersAgentOwnership(t *testing.T) {
	// Static markers for the multi-agent status UI.
	for _, want := range []string{`id="agentsList"`, "j.agents", "agents.map(function(a)", "Owning agent", "data-agent-domain", "data-agent-email", "j.domainManager", "j.emailEnabled"} {
		if !strings.Contains(serverStatsHTML, want) {
			t.Fatalf("server stats template missing multi-agent fragment %q", want)
		}
	}

	// The "/" handler ignores Execute errors, so render here to catch faults.
	tpl := template.Must(template.New("stats").Parse(serverStatsHTML))
	data := map[string]any{
		"Cfg":        tunnel.ServerConfig{},
		"Status":     tunnel.ServerStatus{AgentConnected: true},
		"ConfigPath": "server.json",
		"Msg":        "",
		"Err":        nil,
		"CSRF":       "test-csrf",
		"Routes": []tunnel.RouteConfig{
			{Name: "mc", Proto: "tcp", PublicAddr: ":25565", Agent: "laptop-mc"},
		},
		"RouteCount": 1,
		"WebHTTPS":   false,
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		t.Fatalf("dashboard template execute failed: %v", err)
	}
	if !strings.Contains(buf.String(), "laptop-mc") {
		t.Fatal("rendered dashboard did not include the route's owning agent")
	}
}

// The config page builds a local routeView; if the template references a route
// field that view lacks, Execute errors mid-range and no route cards render.
func TestConfigTemplateRendersRouteCards(t *testing.T) {
	tpl := template.Must(template.New("config").Parse(serverConfigHTML))
	type routeView struct {
		Name, Proto, PublicAddr, LocalAddr, Domain, Agent string
		IsEncrypted, IsDomainEnabled                      bool
	}
	data := map[string]any{
		"Cfg":               tunnel.ServerConfig{},
		"Status":            tunnel.ServerStatus{},
		"ConfigPath":        "server.json",
		"Msg":               "",
		"Err":               nil,
		"CSRF":              "test-csrf",
		"Version":           "test",
		"DomainRenewBefore": "720h",
		"Routes":            []routeView{{Name: "mc", Proto: "tcp", PublicAddr: ":25565", Agent: "laptop-mc"}},
		"RouteCount":        1,
		"Agents":            []string{"default", "laptop-mc", "main-pc"},
		"WebHTTPS":          false,
		"WebTLSCert":        "",
		"WebTLSKey":         "",
		"WebTLSFP":          "",
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		t.Fatalf("config template execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `name="route_0_name"`) || !strings.Contains(out, "mc") {
		t.Fatal("config template did not render the route card")
	}
	// Owning agent must be a dropdown with the route's current owner selected.
	if !strings.Contains(out, `<select name="route_0_agent">`) {
		t.Fatal("config template did not render the owning-agent dropdown")
	}
	if !strings.Contains(out, `value="laptop-mc" selected`) {
		t.Fatal("config template did not pre-select the route's current owner")
	}
	if !strings.Contains(out, `<option value="main-pc"`) {
		t.Fatal("config template did not list other registered agents as options")
	}
}

// The agents list builds innerHTML via esc(); if the helper isn't defined in
// this template, poll() throws once an agent connects and the UI freezes on
// "Syncing" / "No agents known yet".
func TestStatsTemplateDefinesHelpersItCalls(t *testing.T) {
	for _, fn := range []string{"esc", "fmtNum", "setPill"} {
		if !strings.Contains(serverStatsHTML, fn+"(") {
			continue
		}
		if !strings.Contains(serverStatsHTML, "function "+fn+"(") {
			t.Errorf("serverStatsHTML calls %s() but never defines it", fn)
		}
	}
}
