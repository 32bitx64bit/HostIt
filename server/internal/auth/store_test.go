package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempDB(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestOpenClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("db file missing after Close: %v", err)
	}
}

func TestCreateUserAndValidSession(t *testing.T) {
	s, _ := tempDB(t)
	ctx := context.Background()

	err := s.CreateUser(ctx, "alice", "password123")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	userID, ok, err := s.Authenticate(ctx, "alice", "password123")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !ok {
		t.Fatal("Authenticate: expected success")
	}
	if userID == 0 {
		t.Fatal("Authenticate: userID should not be 0")
	}

	sid, err := s.CreateSession(ctx, userID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sid == "" {
		t.Fatal("CreateSession: empty session id")
	}

	gotUserID, valid, err := s.GetSession(ctx, sid, 0)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !valid {
		t.Fatal("GetSession: expected valid session")
	}
	if gotUserID != userID {
		t.Fatalf("GetSession: userID=%d, want %d", gotUserID, userID)
	}
}

func TestCreateUserDuplicateUsername(t *testing.T) {
	s, _ := tempDB(t)
	ctx := context.Background()

	if err := s.CreateUser(ctx, "bob", "pass1"); err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}

	err := s.CreateUser(ctx, "bob", "pass2")
	if err == nil {
		t.Fatal("duplicate CreateUser: expected error")
	}
	if !IsUniqueConstraint(err) {
		t.Fatalf("expected unique constraint error, got: %v", err)
	}
}

func TestGetSessionAndDeleteSession(t *testing.T) {
	s, _ := tempDB(t)
	ctx := context.Background()

	_ = s.CreateUser(ctx, "charlie", "pass")
	userID, _, _ := s.Authenticate(ctx, "charlie", "pass")
	sid, _ := s.CreateSession(ctx, userID, time.Hour)

	_, valid, _ := s.GetSession(ctx, sid, 0)
	if !valid {
		t.Fatal("GetSession: expected valid before delete")
	}

	if err := s.DeleteSession(ctx, sid); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	_, valid, _ = s.GetSession(ctx, sid, 0)
	if valid {
		t.Fatal("GetSession: expected invalid after delete")
	}
}

func TestExpiredSessionCleanup(t *testing.T) {
	s, _ := tempDB(t)
	ctx := context.Background()

	_ = s.CreateUser(ctx, "dave", "pass")
	userID, _, _ := s.Authenticate(ctx, "dave", "pass")

	sid, _ := s.CreateSession(ctx, userID, -1*time.Second)

	_, valid, _ := s.GetSession(ctx, sid, 0)
	if valid {
		t.Fatal("expired session should not be valid")
	}

	if err := s.deleteExpired(ctx); err != nil {
		t.Fatalf("deleteExpired: %v", err)
	}

	_, valid, _ = s.GetSession(ctx, sid, 0)
	if valid {
		t.Fatal("expired session should be gone after cleanup")
	}
}

func TestHasAnyUsers(t *testing.T) {
	s, _ := tempDB(t)
	ctx := context.Background()

	has, err := s.HasAnyUsers(ctx)
	if err != nil {
		t.Fatalf("HasAnyUsers (empty): %v", err)
	}
	if has {
		t.Fatal("HasAnyUsers: expected false for empty db")
	}

	_ = s.CreateUser(ctx, "eve", "pass")
	has, err = s.HasAnyUsers(ctx)
	if err != nil {
		t.Fatalf("HasAnyUsers (non-empty): %v", err)
	}
	if !has {
		t.Fatal("HasAnyUsers: expected true after creating user")
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	s, _ := tempDB(t)
	ctx := context.Background()

	_ = s.CreateUser(ctx, "frank", "correct")

	_, ok, err := s.Authenticate(ctx, "frank", "wrong")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if ok {
		t.Fatal("Authenticate: expected failure for wrong password")
	}

	_, ok, err = s.Authenticate(ctx, "nonexistent", "pass")
	if err != nil {
		t.Fatalf("Authenticate nonexistent: %v", err)
	}
	if ok {
		t.Fatal("Authenticate: expected failure for nonexistent user")
	}
}
