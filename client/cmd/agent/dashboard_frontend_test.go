package main

import (
	"regexp"
	"strings"
	"testing"
)

func TestFrontendTemplatesUnwrapAPIEnvelope(t *testing.T) {
	templates := map[string]string{
		"dashboard": agentHomeHTML,
		"controls":  agentControlsHTML,
		"mail":      agentMailHTML,
		"apps":      agentAppsHTML,
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
	if strings.Contains(agentHomeHTML, "type=\"password\" id=\"tokenInput\"") {
		t.Fatal("token input should stay in the visible text state")
	}
	if strings.Contains(agentHomeHTML, "getElementById('tokenInput')") || strings.Contains(agentHomeHTML, "Show</button>") || strings.Contains(agentHomeHTML, "Hide") {
		t.Fatal("token input should not render a show/hide toggle")
	}
	if !strings.Contains(agentHomeHTML, "type=\"text\" id=\"tokenInput\"") {
		t.Fatal("token input should render as a text input")
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
