package main

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func mustReadAgentTemplate(t *testing.T, path string) string {
	t.Helper()
	data, err := fs.ReadFile(templateFS, path)
	if err != nil {
		t.Fatalf("cannot read template %s: %v", path, err)
	}
	return string(data)
}

func TestFrontendTemplatesUnwrapAPIEnvelope(t *testing.T) {
	templates := map[string]string{
		"dashboard": mustReadAgentTemplate(t, "templates/home.html"),
		"controls":  mustReadAgentTemplate(t, "templates/controls.html"),
		"mail":      mustReadAgentTemplate(t, "templates/mail.html"),
		"apps":      mustReadAgentTemplate(t, "templates/apps.html"),
	}

	directJSONCall := regexp.MustCompile(`(?:await\s+[A-Za-z0-9_]+\.json\(\)|return\s+[A-Za-z0-9_]+\.json\(\)|\.then\(function\([A-Za-z0-9_]+\)\{return\s+[A-Za-z0-9_]+\.json\(\)\}\))`)

	for name, html := range templates {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(html, "function apiData(payload)") || !strings.Contains(html, "async function readAPI") {
				t.Fatalf("template is missing API envelope unwrap helpers")
			}

			for _, loc := range directJSONCall.FindAllStringIndex(html, -1) {
				line := containingLine(html, loc[0], loc[1])
				if !strings.Contains(line, "apiData(await") {
					t.Fatalf("direct JSON response read bypasses API envelope unwrap helper: %s", strings.TrimSpace(line))
				}
			}
		})
	}
}

func TestTokenInputHasNoDeadShowHideToggle(t *testing.T) {
	html := mustReadAgentTemplate(t, "templates/home.html")
	if strings.Contains(html, `type="password" id="tokenInput"`) {
		t.Fatal("token input should stay in the visible text state")
	}
	if strings.Contains(html, "getElementById('tokenInput')") || strings.Contains(html, "Show</button>") || strings.Contains(html, "Hide") {
		t.Fatal("token input should not render a show/hide toggle")
	}
	if !strings.Contains(html, `type="text" id="tokenInput"`) {
		t.Fatal("token input should render as a text input")
	}
}

func TestStatusPollersRecoverAfterDashboardRestart(t *testing.T) {
	for name, html := range map[string]string{
		"dashboard": mustReadAgentTemplate(t, "templates/home.html"),
		"apps":      mustReadAgentTemplate(t, "templates/apps.html"),
	} {
		t.Run(name, func(t *testing.T) {
			for _, want := range []string{"function scheduleReload()", "async function fetchJSON(url)", "AbortController", "Accept':'application/json'", "Syncing"} {
				if !strings.Contains(html, want) {
					t.Fatalf("template missing restart recovery fragment %q", want)
				}
			}
		})
	}
}

func TestHomeStatusTileRecoversToSyncingOnFetchFailure(t *testing.T) {
	html := mustReadAgentTemplate(t, "templates/home.html")
	// poll() must wrap its body in try/catch so a transient fetch failure
	// (e.g. during an agent restart) sets the Service and Connection tiles
	// to [SYNCING]/warn instead of leaving a stale [DISCONNECTED] label.
	if !strings.Contains(html, "setTile('tileConn','[SYNCING]','warn')") {
		t.Fatal("home template should set the Connection tile to [SYNCING]/warn in the poll catch block")
	}
	if !strings.Contains(html, "setTile('tileService','[SYNCING]','warn')") {
		t.Fatal("home template should set the Service tile to [SYNCING]/warn in the poll catch block")
	}
}

func TestHomeFetchJSONDoesNotReloadOnTransientErrors(t *testing.T) {
	html := mustReadAgentTemplate(t, "templates/home.html")
	// fetchJSON should use finally (not catch+scheduleReload+return null)
	// so transient network errors throw to the poll() caller instead of
	// triggering a disruptive full-page reload. scheduleReload should only
	// fire for redirect/content-type mismatches (dashboard changed).
	if !strings.Contains(html, "finally{clearTimeout(t);}") {
		t.Fatal("home fetchJSON should use finally to clear the timer and let errors propagate")
	}
}

func containingLine(s string, start, end int) string {
	lineStart := strings.LastIndex(s[:start], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}
	lineEndRel := strings.Index(s[end:], "\n")
	if lineEndRel == -1 {
		return s[lineStart:]
	}
	return s[lineStart : end+lineEndRel]
}
