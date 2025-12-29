package tunnel

import "testing"

func TestNormalizeRoutes_GeneratesUniqueNamesForBlank(t *testing.T) {
	cfg := ServerConfig{Routes: []RouteConfig{
		{Name: "", Proto: "tcp", PublicAddr: ":10000"},
		{Name: " ", Proto: "tcp", PublicAddr: ":10001"},
		{Name: "", Proto: "udp", PublicAddr: ":10002"},
	}}

	normalizeRoutes(&cfg)

	if cfg.Routes[0].Name != "default" {
		t.Fatalf("route0 name=%q, want %q", cfg.Routes[0].Name, "default")
	}
	if cfg.Routes[1].Name != "default-2" {
		t.Fatalf("route1 name=%q, want %q", cfg.Routes[1].Name, "default-2")
	}
	if cfg.Routes[2].Name != "default-3" {
		t.Fatalf("route2 name=%q, want %q", cfg.Routes[2].Name, "default-3")
	}
}

func TestNormalizeRoutes_DedupesExplicitDuplicateNames(t *testing.T) {
	cfg := ServerConfig{Routes: []RouteConfig{
		{Name: "app", Proto: "tcp", PublicAddr: ":10000"},
		{Name: "app", Proto: "tcp", PublicAddr: ":10001"},
		{Name: "app-2", Proto: "tcp", PublicAddr: ":10002"},
		{Name: "app", Proto: "udp", PublicAddr: ":10003"},
	}}

	normalizeRoutes(&cfg)

	got := []string{cfg.Routes[0].Name, cfg.Routes[1].Name, cfg.Routes[2].Name, cfg.Routes[3].Name}
	want := []string{"app", "app-3", "app-2", "app-4"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("route%d name=%q, want %q (all=%v)", i, got[i], want[i], got)
		}
	}
}
