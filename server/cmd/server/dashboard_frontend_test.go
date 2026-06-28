package main

import (
	"bytes"
	"html/template"
	"io/fs"
	"strings"
	"testing"

	"hostit/server/internal/tunnel"
)

func mustReadTemplate(t *testing.T, path string) string {
	t.Helper()
	data, err := fs.ReadFile(templateFS, path)
	if err != nil {
		t.Fatalf("cannot read template %s: %v", path, err)
	}
	return string(data)
}

func TestStatsPollerRecoversAfterDashboardRestart(t *testing.T) {
	html := mustReadTemplate(t, "templates/stats.html")
	for _, want := range []string{"function scheduleReload()", "async function fetchJSON(url)", "AbortController", "Accept':'application/json'", "Syncing"} {
		if !strings.Contains(html, want) {
			t.Fatalf("server stats template missing restart recovery fragment %q", want)
		}
	}
}

func TestStatsAgentTileRecoversToSyncingOnFetchFailure(t *testing.T) {
	html := mustReadTemplate(t, "templates/stats.html")
	// poll() must wrap its body in try/catch so a transient fetch failure
	// (e.g. during an agent or server restart) sets the Agent tile to
	// [SYNCING]/warn instead of leaving a stale [DISCONNECTED] label.
	if !strings.Contains(html, "sg.textContent='[SYNCING]'") {
		t.Fatal("stats template should set the Agent tile to [SYNCING] in the poll catch block")
	}
	if !strings.Contains(html, "sg.className='v warn'") {
		t.Fatal("stats template should set the Agent tile to warn state in the poll catch block")
	}
	// fetchJSON should use finally (not catch+scheduleReload+return null)
	// so transient network errors throw to the poll() caller instead of
	// triggering a disruptive full-page reload.
	if !strings.Contains(html, "finally{clearTimeout(t);}") {
		t.Fatal("stats fetchJSON should use finally to clear the timer and let errors propagate")
	}
}

func TestDashboardTemplateRendersAndPollsStats(t *testing.T) {
	html := mustReadTemplate(t, "templates/stats.html")
	for _, want := range []string{"/api/stats", "renderAgents", "renderRoutes", "renderBand", "renderConn"} {
		if !strings.Contains(html, want) {
			t.Fatalf("server stats template missing UI function %q", want)
		}
	}
	tpl := template.Must(template.ParseFS(templateFS, "templates/stats.html"))
	data := map[string]any{
		"CSRF":    "test-csrf",
		"Version": "test",
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		t.Fatalf("dashboard template execute failed: %v", err)
	}
	if !strings.Contains(buf.String(), "/api/stats") {
		t.Fatal("rendered dashboard did not reference /api/stats")
	}
}

func TestConfigTemplateRenders(t *testing.T) {
	html := mustReadTemplate(t, "templates/config.html")
	for _, want := range []string{"/config/save", "route_count"} {
		if !strings.Contains(html, want) {
			t.Fatalf("config template missing %q", want)
		}
	}
	tpl := template.Must(template.ParseFS(templateFS, "templates/config.html"))
	data := map[string]any{
		"CSRF":              "test-csrf",
		"Version":           "test",
		"DomainRenewBefore": "720h",
		"Cfg":               tunnel.ServerConfig{},
		"Status":            tunnel.ServerStatus{},
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		t.Fatalf("config template execute failed: %v", err)
	}
}

func TestStatsTemplateDefinesHelpersItCalls(t *testing.T) {
	html := mustReadTemplate(t, "templates/stats.html")
	for _, fn := range []string{"fmtNum", "fmtBytes", "fmtMiB"} {
		if !strings.Contains(html, fn+"(") {
			continue
		}
		if !strings.Contains(html, "function "+fn+"(") {
			t.Errorf("stats template calls %s() but never defines it", fn)
		}
	}
}
