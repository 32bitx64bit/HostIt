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

func runRoutePersistenceHandler(t *testing.T, wantType byte, handler func(net.Conn)) []byte {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		handler(serverConn)
	}()

	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	pkt, err := protocol.ReadPacket(clientConn)
	clientConn.Close()
	if err != nil {
		t.Fatalf("read handler response: %v", err)
	}
	if pkt.Type != wantType {
		t.Fatalf("handler packet type = %d, want %d", pkt.Type, wantType)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("route handler did not return")
	}
	return pkt.Payload
}

func assertPersistedRouteIdentity(t *testing.T, before, after *appstore.AppRoute) {
	t.Helper()
	if after == nil {
		t.Fatal("persisted route is nil")
	}
	if after.ID != before.ID || after.AppID != before.AppID || !after.CreatedAt.Equal(before.CreatedAt) {
		t.Fatalf("persisted route identity changed: before=%+v after=%+v", before, after)
	}
}

func TestRouteHandlersPersistUpdatesInPlace(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "routes.db")
	store, err := appstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if store != nil {
			_ = store.Close()
		}
	})

	app, err := store.CreateApplication(ctx, "sunshine", "hash")
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.AddRoute(ctx, app.ID, appstore.AppRoute{
		RouteName:  "sunshine-control",
		Proto:      "tcp",
		PublicAddr: ":47999",
		LocalAddr:  "127.0.0.1:47999",
		AgentID:    "agent-a",
		Encrypted:  true,
		Enabled:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := NewServer(ServerConfig{
		DomainManagerEnabled: true,
		DomainBase:           "example.com",
	}, store)
	session := &agentSession{agentID: "agent-a"}

	confirmPayload, err := json.Marshal(apitypes.RouteConfirm{
		RequestID: "confirm-1",
		Name:      before.RouteName,
		Domain:    "control.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	responsePayload := runRoutePersistenceHandler(t, protocol.TypeRouteAck, func(conn net.Conn) {
		srv.handleRouteConfirm(conn, session, confirmPayload)
	})
	var confirmAck apitypes.RouteAck
	if err := json.Unmarshal(responsePayload, &confirmAck); err != nil {
		t.Fatal(err)
	}
	if confirmAck.Status != "active" {
		t.Fatalf("confirm status = %q, error=%q", confirmAck.Status, confirmAck.Error)
	}

	confirmed, err := store.GetRouteByRouteName(ctx, before.RouteName)
	if err != nil {
		t.Fatal(err)
	}
	assertPersistedRouteIdentity(t, before, confirmed)
	if confirmed.Domain != "control.example.com" || !confirmed.DomainEnabled || !confirmed.Encrypted || confirmed.AgentID != "agent-a" {
		t.Fatalf("confirmed persisted route = %+v", confirmed)
	}

	disableEncryption := false
	updatePayload, err := json.Marshal(apitypes.RouteUpdate{
		RequestID: "update-1",
		Name:      before.RouteName,
		LocalAddr: "127.0.0.1:48000",
		Domain:    "input.example.com",
		Encrypted: &disableEncryption,
	})
	if err != nil {
		t.Fatal(err)
	}
	responsePayload = runRoutePersistenceHandler(t, protocol.TypeRouteUpdateAck, func(conn net.Conn) {
		srv.handleRouteUpdate(conn, session, updatePayload)
	})
	var updateAck apitypes.RouteUpdateAck
	if err := json.Unmarshal(responsePayload, &updateAck); err != nil {
		t.Fatal(err)
	}
	if updateAck.Status != "updated" {
		t.Fatalf("update status = %q, error=%q", updateAck.Status, updateAck.Error)
	}

	updated, err := store.GetRouteByRouteName(ctx, before.RouteName)
	if err != nil {
		t.Fatal(err)
	}
	assertPersistedRouteIdentity(t, before, updated)
	if updated.Proto != "tcp" || updated.PublicAddr != ":47999" || updated.LocalAddr != "127.0.0.1:48000" || updated.AgentID != "agent-a" || updated.Encrypted || updated.Domain != "input.example.com" || !updated.DomainEnabled || !updated.Enabled {
		t.Fatalf("updated persisted route = %+v", updated)
	}

	appAfter, err := store.GetApplication(ctx, app.Label)
	if err != nil {
		t.Fatal(err)
	}
	if appAfter == nil || len(appAfter.Routes) != 1 || appAfter.Routes[0].ID != before.ID {
		t.Fatalf("application ownership changed: %+v", appAfter)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = nil
	reopened, err := appstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	persisted, err := reopened.GetRouteByRouteName(ctx, before.RouteName)
	if err != nil {
		t.Fatal(err)
	}
	assertPersistedRouteIdentity(t, before, persisted)
	if persisted.LocalAddr != "127.0.0.1:48000" || persisted.Domain != "input.example.com" || persisted.Encrypted {
		t.Fatalf("reopened persisted route = %+v", persisted)
	}
	reopenedApp, err := reopened.GetApplication(ctx, app.Label)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedApp == nil || len(reopenedApp.Routes) != 1 || reopenedApp.Routes[0].ID != before.ID {
		t.Fatalf("reopened application ownership changed: %+v", reopenedApp)
	}
}
