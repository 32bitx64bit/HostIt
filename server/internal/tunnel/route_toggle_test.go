package tunnel

import (
	"testing"
)

func TestSetRouteEnabledPersistsInCache(t *testing.T) {
	srv := NewServer(ServerConfig{
		Routes: []RouteConfig{{Name: "web", Proto: "tcp", PublicAddr: ":8080", Agent: "main-pc"}},
	}, nil)

	if !srv.GetRouteEnabled("web") {
		t.Fatalf("GetRouteEnabled before toggle = false, want true (default)")
	}

	if !srv.SetRouteEnabled("web", false) {
		t.Fatal("SetRouteEnabled returned false (route not found)")
	}

	if srv.GetRouteEnabled("web") {
		t.Fatalf("GetRouteEnabled after toggle = true, want false")
	}

	// Toggling back on works too.
	srv.SetRouteEnabled("web", true)
	if !srv.GetRouteEnabled("web") {
		t.Fatalf("GetRouteEnabled after re-enable = false, want true")
	}
}
