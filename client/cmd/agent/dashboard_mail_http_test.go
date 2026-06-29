package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hostit/client/internal/agent"
	"hostit/client/internal/mail"
	"hostit/shared/emailcfg"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func smtpDeliver(t *testing.T, addr, from, to, body string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	read := func() string {
		s, err := rw.ReadString('\n')
		if err != nil {
			t.Fatalf("smtp read: %v", err)
		}
		return s
	}
	w := func(s string) {
		if _, err := fmt.Fprintf(rw, "%s\r\n", s); err != nil {
			t.Fatalf("smtp write: %v", err)
		}
		_ = rw.Flush()
	}
	_ = read()
	w("EHLO test")
	for {
		line := read()
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	w("MAIL FROM:<" + from + ">")
	_ = read()
	w("RCPT TO:<" + to + ">")
	_ = read()
	w("DATA")
	_ = read()
	if _, err := rw.WriteString(body + "\r\n.\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = rw.Flush()
	_ = read()
	w("QUIT")
}

func TestMailHTTPInboxTwoAccounts(t *testing.T) {
	mailDir := t.TempDir()
	svc, err := mail.NewService(mailDir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatal(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	inbound := freePort(t)
	if err := svc.ApplyConfig(emailcfg.Config{
		Enabled:           true,
		Domain:            "example.com",
		SubmissionAddr:    "127.0.0.1:0",
		SubmissionTLSAddr: "127.0.0.1:0",
		IMAPAddr:          "127.0.0.1:0",
		IMAPTLSAddr:       "127.0.0.1:0",
		InboundSMTP:       true,
		InboundSMTPAddr:   inbound,
		Accounts: []emailcfg.Account{
			{Username: "alice", PasswordHash: string(hash), PasswordSet: true, Enabled: true},
			{Username: "bob", PasswordHash: string(hash), PasswordSet: true, Enabled: true},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Deliver one message to bob, one to alice.
	smtpDeliver(t, inbound, "ext@example.net", "bob@example.com", "From: ext@example.net\r\nTo: bob@example.com\r\nSubject: hi bob\r\n\r\nbody bob")
	smtpDeliver(t, inbound, "ext@example.net", "alice@example.com", "From: ext@example.net\r\nTo: alice@example.com\r\nSubject: hi alice\r\n\r\nbody alice")

	dctrl := newAgentController(ctx, agent.Config{})
	cfgPath := filepath.Join(mailDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	go func() { _ = serveAgentDashboard(ctx, addr, cfgPath, dctrl, svc) }()
	base := "http://" + addr
	if err := waitForListen(base); err != nil {
		t.Fatalf("dashboard never started: %v", err)
	}

	post := func(url string, body map[string]string) (int, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Host = addr
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %s: %v", url, err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return res.StatusCode, out
	}

	for _, tc := range []struct{ user, want string }{
		{"alice", "hi alice"},
		{"bob", "hi bob"},
		{"alice@example.com", "hi alice"}, // address login
	} {
		code, out := post(base+"/api/mail/inbox", map[string]string{"username": tc.user, "password": "Password123"})
		if code != 200 {
			t.Fatalf("inbox %q status = %d, want 200", tc.user, code)
		}
		data, _ := out["data"].([]any)
		if len(data) != 1 {
			t.Fatalf("inbox %q = %d messages, want 1 (got %v)", tc.user, len(data), out)
		}
		row, _ := data[0].(map[string]any)
		if row["subject"] != tc.want {
			t.Fatalf("inbox %q subject = %v, want %q", tc.user, row["subject"], tc.want)
		}
		t.Logf("inbox %q -> %q OK", tc.user, row["subject"])
	}
}

func waitForListen(base string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, err := http.Get(base + "/healthz")
		if err == nil {
			_ = res.Body.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return context.DeadlineExceeded
}

// TestAgentAPIRejectsNonJSONContentType locks in the CSRF defense for the
// dual-use JSON API: a forged cross-origin "simple" request (text/plain or
// form-encoded) is rejected with 415 before reaching the handler, while a real
// application/json request from the SDK passes the guard.
func TestAgentAPIRejectsNonJSONContentType(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dctrl := newAgentController(ctx, agent.Config{})
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	go func() { _ = serveAgentDashboard(ctx, addr, cfgPath, dctrl, nil) }()
	base := "http://" + addr
	if err := waitForListen(base); err != nil {
		t.Fatalf("dashboard never started: %v", err)
	}

	body := `{"name":"x","proto":"tcp","local_port":3000}`
	do := func(ct string) int {
		req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/register", strings.NewReader(body))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		req.Host = addr
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}

	// Forgeable content types must be rejected before the handler runs.
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", ""} {
		if code := do(ct); code != http.StatusUnsupportedMediaType {
			t.Fatalf("Content-Type %q: status = %d, want 415", ct, code)
		}
	}

	// application/json passes the guard (agent isn't connected, so the handler
	// itself returns 503 — the point is it is NOT a 415 from the guard).
	if code := do("application/json"); code == http.StatusUnsupportedMediaType {
		t.Fatalf("application/json was rejected by the content-type guard, want pass-through")
	}
}
