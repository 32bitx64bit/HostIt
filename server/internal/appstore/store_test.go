package appstore

import (
	"context"
	"os"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	f, err := os.CreateTemp("", "appstore-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	t.Cleanup(func() { os.Remove(path) })
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenAndClose(t *testing.T) {
	f, err := os.CreateTemp("", "appstore-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestCreateApplication(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	app, err := s.CreateApplication(ctx, "myapp", "hash123")
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	if app.ID == 0 {
		t.Fatal("app.ID should not be 0")
	}
	if app.Label != "myapp" {
		t.Fatalf("Label=%q, want %q", app.Label, "myapp")
	}
	if app.APIKeyHash != "hash123" {
		t.Fatalf("APIKeyHash=%q, want %q", app.APIKeyHash, "hash123")
	}
	if !app.Enabled {
		t.Fatal("Enabled should be true")
	}
	if app.CreatedAt.IsZero() {
		t.Fatal("CreatedAt should not be zero")
	}
}

func TestGetApplication(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	app, err := s.GetApplication(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetApplication nonexistent: %v", err)
	}
	if app != nil {
		t.Fatal("expected nil for nonexistent app")
	}

	created, _ := s.CreateApplication(ctx, "myapp", "hash123")

	got, err := s.GetApplication(ctx, "myapp")
	if err != nil {
		t.Fatalf("GetApplication: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("ID=%d, want %d", got.ID, created.ID)
	}
	if got.Label != "myapp" {
		t.Fatalf("Label=%q, want %q", got.Label, "myapp")
	}
	if len(got.Routes) != 0 {
		t.Fatalf("Routes=%d, want 0", len(got.Routes))
	}
}

func TestListApplications(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	apps, err := s.ListApplications(ctx)
	if err != nil {
		t.Fatalf("ListApplications empty: %v", err)
	}
	if len(apps) != 0 {
		t.Fatalf("expected 0 apps, got %d", len(apps))
	}

	s.CreateApplication(ctx, "app1", "h1")
	s.CreateApplication(ctx, "app2", "h2")

	apps, err = s.ListApplications(ctx)
	if err != nil {
		t.Fatalf("ListApplications: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(apps))
	}
	if apps[0].Label != "app1" {
		t.Fatalf("apps[0].Label=%q, want %q", apps[0].Label, "app1")
	}
	if apps[1].Label != "app2" {
		t.Fatalf("apps[1].Label=%q, want %q", apps[1].Label, "app2")
	}
}

func TestSetApplicationEnabled(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	app, _ := s.CreateApplication(ctx, "myapp", "h1")
	r1, _ := s.AddRoute(ctx, app.ID, AppRoute{RouteName: "r1", Proto: "tcp", Enabled: true})
	r2, _ := s.AddRoute(ctx, app.ID, AppRoute{RouteName: "r2", Proto: "tcp", Enabled: true})

	if err := s.SetApplicationEnabled(ctx, "myapp", false); err != nil {
		t.Fatalf("SetApplicationEnabled: %v", err)
	}

	got, _ := s.GetApplication(ctx, "myapp")
	if got.Enabled {
		t.Fatal("app should be disabled")
	}

	for _, r := range got.Routes {
		if r.Enabled {
			t.Fatalf("route %s should be disabled", r.RouteName)
		}
	}

	if err := s.SetApplicationEnabled(ctx, "myapp", true); err != nil {
		t.Fatalf("SetApplicationEnabled true: %v", err)
	}

	got, _ = s.GetApplication(ctx, "myapp")
	if !got.Enabled {
		t.Fatal("app should be enabled")
	}
	for _, r := range got.Routes {
		if !r.Enabled {
			t.Fatalf("route %s should be enabled", r.RouteName)
		}
	}

	_ = r1
	_ = r2
}

func TestDeleteApplication(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	app, _ := s.CreateApplication(ctx, "myapp", "h1")
	s.AddRoute(ctx, app.ID, AppRoute{RouteName: "r1", Proto: "tcp"})

	if err := s.DeleteApplication(ctx, "myapp"); err != nil {
		t.Fatalf("DeleteApplication: %v", err)
	}

	got, _ := s.GetApplication(ctx, "myapp")
	if got != nil {
		t.Fatal("app should be nil after delete")
	}

	routes, _ := s.ListRoutes(ctx)
	if len(routes) != 0 {
		t.Fatalf("routes should be empty after cascade delete, got %d", len(routes))
	}

	if err := s.DeleteApplication(ctx, "nonexistent"); err == nil {
		t.Fatal("expected error deleting nonexistent app")
	}
}

func TestAddRoute(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	app, _ := s.CreateApplication(ctx, "myapp", "h1")

	r, err := s.AddRoute(ctx, app.ID, AppRoute{
		RouteName:     "myroute",
		Proto:         "tcp",
		PublicAddr:    "1.2.3.4:80",
		LocalAddr:     "127.0.0.1:8080",
		Encrypted:     true,
		Domain:        "example.com",
		DomainEnabled: true,
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if r.ID == 0 {
		t.Fatal("route ID should not be 0")
	}
	if r.AppID != app.ID {
		t.Fatalf("AppID=%d, want %d", r.AppID, app.ID)
	}
	if r.RouteName != "myroute" {
		t.Fatalf("RouteName=%q, want %q", r.RouteName, "myroute")
	}
	if r.Proto != "tcp" {
		t.Fatalf("Proto=%q, want %q", r.Proto, "tcp")
	}
	if r.PublicAddr != "1.2.3.4:80" {
		t.Fatalf("PublicAddr=%q, want %q", r.PublicAddr, "1.2.3.4:80")
	}
	if r.LocalAddr != "127.0.0.1:8080" {
		t.Fatalf("LocalAddr=%q, want %q", r.LocalAddr, "127.0.0.1:8080")
	}
	if !r.Encrypted {
		t.Fatal("Encrypted should be true")
	}
	if r.Domain != "example.com" {
		t.Fatalf("Domain=%q, want %q", r.Domain, "example.com")
	}
	if !r.DomainEnabled {
		t.Fatal("DomainEnabled should be true")
	}
	if !r.Enabled {
		t.Fatal("Enabled should be true")
	}
	if r.CreatedAt.IsZero() {
		t.Fatal("CreatedAt should not be zero")
	}

	got, _ := s.GetApplication(ctx, "myapp")
	if len(got.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(got.Routes))
	}
}

func TestRemoveRoute(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	app, _ := s.CreateApplication(ctx, "myapp", "h1")
	s.AddRoute(ctx, app.ID, AppRoute{RouteName: "r1", Proto: "tcp"})
	s.AddRoute(ctx, app.ID, AppRoute{RouteName: "r2", Proto: "tcp"})

	if err := s.RemoveRoute(ctx, "r1"); err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}

	got, _ := s.GetApplication(ctx, "myapp")
	if len(got.Routes) != 1 {
		t.Fatalf("expected 1 route after remove, got %d", len(got.Routes))
	}
	if got.Routes[0].RouteName != "r2" {
		t.Fatalf("remaining route=%q, want %q", got.Routes[0].RouteName, "r2")
	}

	if err := s.RemoveRoute(ctx, "nonexistent"); err == nil {
		t.Fatal("expected error removing nonexistent route")
	}
}

func TestSetRouteEnabled(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	app, _ := s.CreateApplication(ctx, "myapp", "h1")
	s.AddRoute(ctx, app.ID, AppRoute{RouteName: "r1", Proto: "tcp", Enabled: true})

	if err := s.SetRouteEnabled(ctx, "r1", false); err != nil {
		t.Fatalf("SetRouteEnabled: %v", err)
	}

	r, _ := s.GetRouteByRouteName(ctx, "r1")
	if r.Enabled {
		t.Fatal("route should be disabled")
	}

	if err := s.SetRouteEnabled(ctx, "r1", true); err != nil {
		t.Fatalf("SetRouteEnabled true: %v", err)
	}

	r, _ = s.GetRouteByRouteName(ctx, "r1")
	if !r.Enabled {
		t.Fatal("route should be enabled")
	}

	if err := s.SetRouteEnabled(ctx, "nonexistent", true); err == nil {
		t.Fatal("expected error for nonexistent route")
	}
}

func TestListRoutes(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	routes, err := s.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes empty: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("expected 0 routes, got %d", len(routes))
	}

	app1, _ := s.CreateApplication(ctx, "app1", "h1")
	app2, _ := s.CreateApplication(ctx, "app2", "h2")
	s.AddRoute(ctx, app1.ID, AppRoute{RouteName: "r1", Proto: "tcp"})
	s.AddRoute(ctx, app1.ID, AppRoute{RouteName: "r2", Proto: "udp"})
	s.AddRoute(ctx, app2.ID, AppRoute{RouteName: "r3", Proto: "tcp"})

	routes, err = s.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	if routes[0].RouteName != "r1" {
		t.Fatalf("routes[0].RouteName=%q, want %q", routes[0].RouteName, "r1")
	}
	if routes[1].Proto != "udp" {
		t.Fatalf("routes[1].Proto=%q, want %q", routes[1].Proto, "udp")
	}
	if routes[2].AppID != app2.ID {
		t.Fatalf("routes[2].AppID=%d, want %d", routes[2].AppID, app2.ID)
	}
}

func TestFindApplicationByRouteName(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	found, err := s.FindApplicationByRouteName(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("FindApplicationByRouteName nonexistent: %v", err)
	}
	if found != nil {
		t.Fatal("expected nil for nonexistent route")
	}

	app, _ := s.CreateApplication(ctx, "myapp", "h1")
	s.AddRoute(ctx, app.ID, AppRoute{RouteName: "myroute", Proto: "tcp"})

	found, err = s.FindApplicationByRouteName(ctx, "myroute")
	if err != nil {
		t.Fatalf("FindApplicationByRouteName: %v", err)
	}
	if found == nil {
		t.Fatal("expected app, got nil")
	}
	if found.Label != "myapp" {
		t.Fatalf("Label=%q, want %q", found.Label, "myapp")
	}
	if len(found.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(found.Routes))
	}
	if found.Routes[0].RouteName != "myroute" {
		t.Fatalf("RouteName=%q, want %q", found.Routes[0].RouteName, "myroute")
	}
}
