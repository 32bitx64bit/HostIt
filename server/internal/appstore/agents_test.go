package appstore

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestResolveAgentClaimReassumeConflict(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	keyA := []byte("key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	keyB := []byte("key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	// First claim of "laptop" by key A (trust-on-first-use).
	got, conflict, err := s.ResolveAgent(ctx, keyA, "laptop")
	if err != nil || conflict || got != "laptop" {
		t.Fatalf("claim: got=%q conflict=%v err=%v", got, conflict, err)
	}

	// Same key proposing a different ID still re-assumes its registered ID.
	got, conflict, err = s.ResolveAgent(ctx, keyA, "something-else")
	if err != nil || conflict || got != "laptop" {
		t.Fatalf("re-assume: got=%q conflict=%v err=%v", got, conflict, err)
	}

	// A different key claiming the taken ID must conflict.
	_, conflict, err = s.ResolveAgent(ctx, keyB, "laptop")
	if err != nil || !conflict {
		t.Fatalf("conflict expected: conflict=%v err=%v", conflict, err)
	}

	// That key can still claim a free ID.
	got, conflict, err = s.ResolveAgent(ctx, keyB, "desktop")
	if err != nil || conflict || got != "desktop" {
		t.Fatalf("second claim: got=%q conflict=%v err=%v", got, conflict, err)
	}
}

func TestRenameAndForgetAgent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	keyA := []byte("key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	keyB := []byte("key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	s.ResolveAgent(ctx, keyA, "laptop")
	s.ResolveAgent(ctx, keyB, "desktop")

	if err := s.RenameAgent(ctx, "laptop", "laptop-mc"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	// Key A now re-assumes the new ID.
	if got, _, _ := s.ResolveAgent(ctx, keyA, "laptop"); got != "laptop-mc" {
		t.Fatalf("after rename got %q, want laptop-mc", got)
	}
	// Renaming onto a taken ID fails.
	if err := s.RenameAgent(ctx, "laptop-mc", "desktop"); err == nil {
		t.Fatal("rename onto taken id should fail")
	}
	// Renaming an unknown ID reports no rows.
	if err := s.RenameAgent(ctx, "nope", "whatever"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("rename unknown = %v, want ErrNoRows", err)
	}

	if err := s.DeleteAgent(ctx, "laptop-mc"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	// After forget the ID is free and key A re-claims it fresh.
	if got, conflict, _ := s.ResolveAgent(ctx, keyA, "laptop-mc"); conflict || got != "laptop-mc" {
		t.Fatalf("re-claim after forget: got=%q conflict=%v", got, conflict)
	}
}

func TestReassignRoutesAgent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	app, err := s.CreateApplication(ctx, "app", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRoute(ctx, app.ID, AppRoute{RouteName: "r1", Proto: "tcp", AgentID: "old", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRoute(ctx, app.ID, AppRoute{RouteName: "r2", Proto: "tcp", AgentID: "other", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	n, err := s.ReassignRoutesAgent(ctx, "old", "new")
	if err != nil || n != 1 {
		t.Fatalf("reassign: n=%d err=%v", n, err)
	}
	rt, err := s.GetRouteByRouteName(ctx, "r1")
	if err != nil || rt.AgentID != "new" {
		t.Fatalf("r1 owner = %q err=%v, want new", rt.AgentID, err)
	}
}
