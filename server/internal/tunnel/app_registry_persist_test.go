package tunnel

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"hostit/server/internal/appstore"
	"hostit/shared/apitypes"
	"hostit/shared/protocol"
)

func TestHandleRouteRequestPersistsApplicationForRegistry(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "apps.db")
	store, err := appstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(ServerConfig{
		DynamicPortRange: "31000-31010",
	}, store)
	session := &agentSession{agentID: "agent-a"}

	reqPayload, err := json.Marshal(apitypes.RouteRequest{
		RequestID:  "req-1",
		Name:       "my-app",
		Proto:      "tcp",
		LocalAddr:  "127.0.0.1:3000",
		PublicPort: 31001,
		Source:     "api",
	})
	if err != nil {
		t.Fatal(err)
	}
	responsePayload := runRoutePersistenceHandler(t, protocol.TypeRouteResponse, func(conn net.Conn) {
		srv.handleRouteRequest(conn, session, reqPayload)
	})
	var resp apitypes.RouteResponse
	if err := json.Unmarshal(responsePayload, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "active" {
		t.Fatalf("status = %q error=%q", resp.Status, resp.Error)
	}

	apps, err := srv.ListApps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 {
		t.Fatalf("ListApps len = %d, want 1 (apps=%+v)", len(apps), apps)
	}
	if apps[0].Label != "my-app" || len(apps[0].Routes) != 1 {
		t.Fatalf("app = %+v", apps[0])
	}
	if apps[0].Routes[0].RouteName != "my-app" || apps[0].Routes[0].PublicAddr != ":31001" {
		t.Fatalf("route = %+v", apps[0].Routes[0])
	}
}

func TestHandleRouteConfirmPersistsNewApplication(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "apps-confirm.db")
	store, err := appstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(ServerConfig{
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
		DynamicPortRange:     "31100-31110",
	}, store)
	session := &agentSession{agentID: "agent-a"}

	// Simulate a live dynamic route that was never persisted (pending_domain path).
	enc := false
	domainEnabled := false
	srv.mu.Lock()
	srv.dynamicRoutes["stream"] = dynamicRouteEntry{
		Route: RouteConfig{
			Name:          "stream",
			Proto:         "tcp",
			PublicAddr:    ":31101",
			LocalAddr:     "127.0.0.1:47998",
			Agent:         "agent-a",
			Enabled:       boolPtr(true),
			Encrypted:     &enc,
			DomainEnabled: &domainEnabled,
		},
		CreatedAt: time.Now(),
		Source:    "api",
	}
	srv.mu.Unlock()

	confirmPayload, err := json.Marshal(apitypes.RouteConfirm{
		RequestID: "confirm-1",
		Name:      "stream",
		Domain:    "stream.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	responsePayload := runRoutePersistenceHandler(t, protocol.TypeRouteAck, func(conn net.Conn) {
		srv.handleRouteConfirm(conn, session, confirmPayload)
	})
	var ack apitypes.RouteAck
	if err := json.Unmarshal(responsePayload, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Status != "active" {
		t.Fatalf("confirm status = %q error=%q", ack.Status, ack.Error)
	}

	apps, err := srv.ListApps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 {
		t.Fatalf("ListApps len = %d after confirm, want 1 (apps=%+v)", len(apps), apps)
	}
	if apps[0].Routes[0].Domain != "stream.example.com" {
		t.Fatalf("persisted domain = %+v", apps[0].Routes[0])
	}
}

func TestHandleRouteRequestPersistsAppsJSONSource(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "apps-json.db")
	store, err := appstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(ServerConfig{DynamicPortRange: "31200-31210"}, store)
	session := &agentSession{agentID: "default"}
	reqPayload, _ := json.Marshal(apitypes.RouteRequest{
		RequestID: "req-2", Name: "json-app", Proto: "tcp",
		LocalAddr: "127.0.0.1:3000", PublicPort: 31201, Source: "apps.json",
	})
	responsePayload := runRoutePersistenceHandler(t, protocol.TypeRouteResponse, func(conn net.Conn) {
		srv.handleRouteRequest(conn, session, reqPayload)
	})
	var resp apitypes.RouteResponse
	_ = json.Unmarshal(responsePayload, &resp)
	if resp.Status != "active" {
		t.Fatalf("status = %q error=%q", resp.Status, resp.Error)
	}
	apps, err := srv.ListApps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || apps[0].Label != "json-app" {
		t.Fatalf("ListApps = %+v", apps)
	}
}

func TestUpsertAppRouteUpdatesExistingRegistration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "upsert.db")
	store, err := appstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv := NewServer(ServerConfig{}, store)
	first := appstore.AppRoute{
		RouteName:  "game",
		Proto:      "udp",
		PublicAddr: ":47998",
		LocalAddr:  "127.0.0.1:47998",
		AgentID:    "agent-a",
		Enabled:    true,
	}
	if err := srv.upsertAppRoute(ctx, "game", first); err != nil {
		t.Fatalf("initial upsert: %v", err)
	}
	before, err := store.GetRouteByRouteName(ctx, "game")
	if err != nil || before == nil {
		t.Fatalf("read before: %v %#v", err, before)
	}

	updated := first
	updated.LocalAddr = "127.0.0.1:48000"
	updated.Encrypted = true
	if err := srv.upsertAppRoute(ctx, "game", updated); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	after, err := store.GetRouteByRouteName(ctx, "game")
	if err != nil || after == nil {
		t.Fatalf("read after: %v %#v", err, after)
	}
	if after.ID != before.ID || after.AppID != before.AppID {
		t.Fatalf("identity changed: before=%+v after=%+v", before, after)
	}
	if after.LocalAddr != "127.0.0.1:48000" || !after.Encrypted {
		t.Fatalf("fields not updated: %+v", after)
	}
	apps, err := srv.ListApps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || len(apps[0].Routes) != 1 {
		t.Fatalf("registry = %+v", apps)
	}
}
