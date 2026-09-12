package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"hostit/server/internal/tunnel"
)

func TestParseServerRoutesFormAssignsAgent(t *testing.T) {
	form := url.Values{}
	form.Set("route_count", "2")
	form.Set("route_0_name", "mc")
	form.Set("route_0_proto", "tcp")
	form.Set("route_0_public", ":25565")
	form.Set("route_0_agent", "laptop-mc")
	form.Set("route_1_name", "web")
	form.Set("route_1_proto", "tcp")
	form.Set("route_1_public", ":8080")
	// route_1 leaves agent empty -> OwnerAgent() resolves to "default".

	routes := parseServerRoutesForm(&http.Request{Form: form}, nil)
	if len(routes) != 2 {
		t.Fatalf("want 2 routes, got %d", len(routes))
	}
	if routes[0].Agent != "laptop-mc" {
		t.Errorf("route 0 agent = %q, want laptop-mc", routes[0].Agent)
	}
	if routes[1].OwnerAgent() != "default" {
		t.Errorf("route 1 unset agent resolved to %q, want default", routes[1].OwnerAgent())
	}
}

func TestParseServerRoutesFormPreservesEnabled(t *testing.T) {
	form := url.Values{}
	form.Set("route_count", "1")
	form.Set("route_0_name", "web")
	form.Set("route_0_proto", "tcp")
	form.Set("route_0_public", ":8080")

	// Existing route was toggled OFF from the dashboard.
	off := false
	existing := []tunnel.RouteConfig{{Name: "web", Proto: "tcp", PublicAddr: ":8080", Enabled: &off}}

	routes := parseServerRoutesForm(&http.Request{Form: form}, existing)
	if len(routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(routes))
	}
	if routes[0].IsEnabled() {
		t.Fatalf("route enabled = %v, want false (config save must preserve dashboard toggle)", routes[0].IsEnabled())
	}

	// A brand-new route (no existing match) defaults to enabled.
	form2 := url.Values{}
	form2.Set("route_count", "1")
	form2.Set("route_0_name", "newroute")
	form2.Set("route_0_public", ":9000")
	fresh := parseServerRoutesForm(&http.Request{Form: form2}, existing)
	if !fresh[0].IsEnabled() {
		t.Fatalf("new route should default to enabled, got disabled")
	}
}

func TestParseServerRoutesFormTruncatesLongAgent(t *testing.T) {
	form := url.Values{}
	form.Set("route_count", "1")
	form.Set("route_0_public", ":9000")
	form.Set("route_0_agent", strings.Repeat("x", 300))

	routes := parseServerRoutesForm(&http.Request{Form: form}, nil)
	if len(routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(routes))
	}
	if len(routes[0].Agent) != 255 {
		t.Errorf("over-long agent id not truncated: len=%d", len(routes[0].Agent))
	}
}

func TestSanitizeHostnameInputStripsURLChrome(t *testing.T) {
	cases := map[string]string{
		"":                                 "",
		"example.com":                      "example.com",
		"EXAMPLE.COM.":                     "example.com",
		"https://example.com":              "example.com",
		"http://app.example.com/":          "app.example.com",
		"https://app.example.com:443/path": "app.example.com",
		"app.example.com:443":              "app.example.com",
	}
	for in, want := range cases {
		if got := sanitizeHostnameInput(in); got != want {
			t.Errorf("sanitizeHostnameInput(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseServerRoutesFormSanitizesDomain(t *testing.T) {
	form := url.Values{}
	form.Set("route_count", "1")
	form.Set("route_0_name", "web")
	form.Set("route_0_proto", "tcp")
	form.Set("route_0_local", "127.0.0.1:3000")
	form.Set("route_0_domain", "https://app.example.com:443")
	form.Set("route_0_domain_enabled", "1")

	routes := parseServerRoutesForm(&http.Request{Form: form}, nil)
	if len(routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(routes))
	}
	if routes[0].Domain != "app.example.com" {
		t.Errorf("domain = %q, want app.example.com", routes[0].Domain)
	}
}

func TestParsePairTimeoutForm(t *testing.T) {
	pt, err := parsePairTimeoutForm("10s", 0)
	if err != nil || pt != 10*time.Second {
		t.Fatalf("10s: got %v, %v", pt, err)
	}
	pt, err = parsePairTimeoutForm("10", 0)
	if err != nil || pt != 10*time.Second {
		t.Fatalf("bare 10: got %v, %v", pt, err)
	}
	pt, err = parsePairTimeoutForm("", 8*time.Second)
	if err != nil || pt != 8*time.Second {
		t.Fatalf("empty with fallback: got %v, %v", pt, err)
	}
	if _, err := parsePairTimeoutForm("nope", 10*time.Second); err == nil {
		t.Fatal("expected error for invalid pair timeout")
	}
}

func TestDisableDomainManagerExtras(t *testing.T) {
	on := true
	cfg := tunnel.ServerConfig{
		DomainManagerEnabled: false,
		DomainAutoTLS:        true,
		Routes: []tunnel.RouteConfig{{
			Name:          "web",
			DomainEnabled: &on,
		}},
	}
	disableDomainManagerExtras(&cfg)
	if cfg.DomainAutoTLS {
		t.Fatal("auto TLS should be cleared when domain manager is off")
	}
	if cfg.Routes[0].IsDomainEnabled() {
		t.Fatal("route domain routing should be cleared when domain manager is off")
	}
}
