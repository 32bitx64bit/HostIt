package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"hostit/server/internal/auth"
)

func newTestAuthStore(t *testing.T) *auth.Store {
	t.Helper()
	store, err := auth.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("auth.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestRequireAuth_AllowsRepeatedValidSessionPolling(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.CreateUser(t.Context(), "admin", "Password123"); err != nil {
		t.Fatal(err)
	}
	userID, ok, err := store.Authenticate(t.Context(), "admin", "Password123")
	if err != nil || !ok {
		t.Fatalf("Authenticate() ok=%v err=%v", ok, err)
	}
	sid, err := store.CreateSession(t.Context(), userID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	h := requireAuth(store, false, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 100; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
		rr := httptest.NewRecorder()
		h(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i+1, rr.Code)
		}
	}
}

func TestRequireAuth_RateLimitsInvalidSessionsOnly(t *testing.T) {
	prev := invalidSessionLimiter
	invalidSessionLimiter = newIPRateLimiter(2, time.Minute)
	defer func() { invalidSessionLimiter = prev }()

	store := newTestAuthStore(t)
	if err := store.CreateUser(t.Context(), "admin", "Password123"); err != nil {
		t.Fatal(err)
	}

	h := requireAuth(store, false, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
		req.RemoteAddr = "203.0.113.11:12345"
		req.AddCookie(&http.Cookie{Name: "sid", Value: "bad-session"})
		rr := httptest.NewRecorder()
		h(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("request %d status = %d, want 303", i+1, rr.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
	req.RemoteAddr = "203.0.113.11:12345"
	req.AddCookie(&http.Cookie{Name: "sid", Value: "bad-session"})
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited status = %d, want 429", rr.Code)
	}
}
