package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
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

	routes := parseServerRoutesForm(&http.Request{Form: form})
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

func TestParseServerRoutesFormTruncatesLongAgent(t *testing.T) {
	form := url.Values{}
	form.Set("route_count", "1")
	form.Set("route_0_public", ":9000")
	form.Set("route_0_agent", strings.Repeat("x", 300))

	routes := parseServerRoutesForm(&http.Request{Form: form})
	if len(routes) != 1 {
		t.Fatalf("want 1 route, got %d", len(routes))
	}
	if len(routes[0].Agent) != 255 {
		t.Errorf("over-long agent id not truncated: len=%d", len(routes[0].Agent))
	}
}
