package sdk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- decodeResponse branch coverage ---

func TestDecodeResponseMalformedErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "this is not json")
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.Status(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed error body")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %q, want it to mention status code 500", err.Error())
	}
}

func TestDecodeResponseErrorBodyNoMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		// Valid envelope JSON but with an empty message field.
		json.NewEncoder(w).Encode(map[string]any{"status": "error"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.Status(context.Background())
	if err == nil {
		t.Fatal("expected error for error body without message")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("error = %q, want it to mention status code 502", err.Error())
	}
}

func TestDecodeResponseErrorBodyWithMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorResponse(w, http.StatusBadRequest, "route name already in use")
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.Status(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "route name already in use" {
		t.Fatalf("error = %q, want %q", err.Error(), "route name already in use")
	}
}

func TestDecodeResponseUnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// 2xx but the envelope status is not "ok".
		json.NewEncoder(w).Encode(map[string]any{"status": "pending", "data": nil})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.Status(context.Background())
	if err == nil {
		t.Fatal("expected error for non-ok envelope status")
	}
	if !strings.Contains(err.Error(), "pending") {
		t.Fatalf("error = %q, want it to mention the status", err.Error())
	}
}

func TestDecodeResponseMalformedSuccessBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "{not valid json")
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.Status(context.Background())
	if err == nil {
		t.Fatal("expected error for malformed success body")
	}
}

func TestDecodeResponseMalformedData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Valid envelope, but data cannot unmarshal into StatusResponse.
		io.WriteString(w, `{"status":"ok","data":"not-an-object"}`)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.Status(context.Background())
	if err == nil {
		t.Fatal("expected error for data that does not match the target type")
	}
}

// --- UpdateRoute request-body construction ---

func TestUpdateRouteBuildsBodyNonLoopbackHost(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		writeOKResponse(w, http.StatusOK, RegisterResponse{Status: "updated", RouteName: "myapp"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.UpdateRoute(context.Background(), "myapp", RouteUpdate{
		LocalAddr:  "0.0.0.0:8081",
		PublicPort: 9091,
		Domain:     "myapp.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["name"] != "myapp" {
		t.Fatalf("name = %v, want myapp", got["name"])
	}
	if got["local_port"].(float64) != 8081 {
		t.Fatalf("local_port = %v, want 8081", got["local_port"])
	}
	if got["local_host"] != "0.0.0.0" {
		t.Fatalf("local_host = %v, want 0.0.0.0", got["local_host"])
	}
	if got["public_port"].(float64) != 9091 {
		t.Fatalf("public_port = %v, want 9091", got["public_port"])
	}
	if got["domain"] != "myapp.example.com" {
		t.Fatalf("domain = %v, want myapp.example.com", got["domain"])
	}
}

func TestUpdateRouteOmitsLoopbackHost(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		writeOKResponse(w, http.StatusOK, RegisterResponse{Status: "updated", RouteName: "myapp"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.UpdateRoute(context.Background(), "myapp", RouteUpdate{LocalAddr: "127.0.0.1:8081"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["local_host"]; ok {
		t.Fatalf("local_host should be omitted for loopback, got %v", got["local_host"])
	}
	if got["local_port"].(float64) != 8081 {
		t.Fatalf("local_port = %v, want 8081", got["local_port"])
	}
	if _, ok := got["public_port"]; ok {
		t.Fatalf("public_port should be omitted when zero, got %v", got["public_port"])
	}
}

func TestUpdateRouteEmptyLocalAddr(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		writeOKResponse(w, http.StatusOK, RegisterResponse{Status: "updated", RouteName: "myapp"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.UpdateRoute(context.Background(), "myapp", RouteUpdate{PublicPort: 9091})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["local_port"]; ok {
		t.Fatalf("local_port should be omitted when LocalAddr empty, got %v", got["local_port"])
	}
	if got["public_port"].(float64) != 9091 {
		t.Fatalf("public_port = %v, want 9091", got["public_port"])
	}
}

func TestUpdateRouteInvalidPort(t *testing.T) {
	client := NewClient("http://localhost:8080")
	_, err := client.UpdateRoute(context.Background(), "myapp", RouteUpdate{LocalAddr: "127.0.0.1:notaport"})
	if err == nil {
		t.Fatal("expected error for non-numeric port")
	}
}

// --- Mail request payloads and error paths ---

func TestGetMailMessageSendsMessageID(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		writeOKResponse(w, http.StatusOK, MailMessageFull{
			MailMessage: MailMessage{ID: 42, Subject: "Hi"},
			Body:        "hello",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	msg, err := client.GetMailMessage(context.Background(), "alice", "secret", 42)
	if err != nil {
		t.Fatal(err)
	}
	if got["username"] != "alice" || got["password"] != "secret" {
		t.Fatalf("unexpected credentials in body: %+v", got)
	}
	if got["messageId"].(float64) != 42 {
		t.Fatalf("messageId = %v, want 42", got["messageId"])
	}
	if msg.ID != 42 || msg.Body != "hello" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestDeleteMailMessageSendsMessageID(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mail/delete" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		writeOKResponse(w, http.StatusOK, nil)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.DeleteMailMessage(context.Background(), "alice", "secret", 7); err != nil {
		t.Fatal(err)
	}
	if got["messageId"].(float64) != 7 {
		t.Fatalf("messageId = %v, want 7", got["messageId"])
	}
}

func TestAuthenticateMailInvalidCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorResponse(w, http.StatusUnauthorized, "invalid credentials")
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	addr, err := client.AuthenticateMail(context.Background(), "alice", "wrong")
	if err == nil {
		t.Fatal("expected error for invalid credentials")
	}
	if addr != "" {
		t.Fatalf("address = %q, want empty on error", addr)
	}
}

func TestLockMailServiceUnlock(t *testing.T) {
	var got map[string]bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		writeOKResponse(w, http.StatusOK, map[string]any{"locked": got["locked"]})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.LockMailService(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got["locked"] != false {
		t.Fatalf("locked = %v, want false", got["locked"])
	}
}

func TestMailErrorPaths(t *testing.T) {
	tests := []struct {
		name   string
		method func(c *Client) error
	}{
		{"list_accounts", func(c *Client) error { _, err := c.ListMailAccounts(context.Background()); return err }},
		{"create_account", func(c *Client) error { _, err := c.CreateMailAccount(context.Background(), "a", "p"); return err }},
		{"update_password", func(c *Client) error { return c.UpdateMailAccountPassword(context.Background(), "a", "p") }},
		{"delete_account", func(c *Client) error { return c.DeleteMailAccount(context.Background(), "a") }},
		{"list_messages", func(c *Client) error { _, err := c.ListMailMessages(context.Background(), "a", "p"); return err }},
		{"get_message", func(c *Client) error { _, err := c.GetMailMessage(context.Background(), "a", "p", 1); return err }},
		{"delete_message", func(c *Client) error { return c.DeleteMailMessage(context.Background(), "a", "p", 1) }},
		{"lock", func(c *Client) error { return c.LockMailService(context.Background(), true) }},
		{"route_stats", func(c *Client) error { _, err := c.RouteStats(context.Background(), "x"); return err }},
		{"update_route", func(c *Client) error {
			_, err := c.UpdateRoute(context.Background(), "x", RouteUpdate{PublicPort: 1})
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeErrorResponse(w, http.StatusInternalServerError, "boom")
			}))
			defer srv.Close()
			if err := tc.method(NewClient(srv.URL)); err == nil {
				t.Fatal("expected error from server failure")
			}
		})
	}
}

// --- Register pending (domain selection) flow ---

func TestRegisterPendingDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeOKResponse(w, http.StatusOK, RegisterResponse{
			Status:    "pending_domain",
			RequestID: "req-9",
			RouteName: "myapp",
			AvailableDomains: []DomainOption{
				{Host: "myapp.example.com", Available: true},
				{Host: "taken.example.com", Available: false, Reason: "in use"},
			},
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	resp, err := client.Register(context.Background(), RegisterRequest{Name: "myapp", Proto: "tcp", LocalPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "pending_domain" {
		t.Fatalf("Status = %q, want pending_domain", resp.Status)
	}
	if resp.RequestID != "req-9" {
		t.Fatalf("RequestID = %q, want req-9", resp.RequestID)
	}
	if len(resp.AvailableDomains) != 2 {
		t.Fatalf("len(AvailableDomains) = %d, want 2", len(resp.AvailableDomains))
	}
}

// --- EventsURL scheme handling ---

func TestEventsURLHTTPS(t *testing.T) {
	tests := []struct {
		baseURL string
		want    string
	}{
		{"https://example.com", "wss://example.com/api/v1/events"},
		{"https://example.com/", "wss://example.com/api/v1/events"},
		{"http://localhost:8080", "ws://localhost:8080/api/v1/events"},
	}
	for _, tc := range tests {
		got := NewClient(tc.baseURL).EventsURL()
		if got != tc.want {
			t.Fatalf("EventsURL(%q) = %q, want %q", tc.baseURL, got, tc.want)
		}
	}
}

// --- Network failure and context cancellation ---

func TestNetworkFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // server is now down; connection will be refused

	client := NewClient(url)
	if _, err := client.Status(context.Background()); err == nil {
		t.Fatal("expected error when server is unreachable")
	}
}

func TestContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeOKResponse(w, http.StatusOK, StatusResponse{Connected: true})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the request is made

	client := NewClient(srv.URL)
	if _, err := client.Status(ctx); err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// --- Request method/path verification across the API surface ---

func TestRequestMethodsAndPaths(t *testing.T) {
	type call struct{ method, path string }
	tests := []struct {
		name string
		want call
		do   func(c *Client) error
	}{
		{"register", call{http.MethodPost, "/api/v1/register"}, func(c *Client) error {
			_, err := c.Register(context.Background(), RegisterRequest{Name: "x", Proto: "tcp", LocalPort: 1})
			return err
		}},
		{"list_routes", call{http.MethodGet, "/api/v1/routes"}, func(c *Client) error {
			_, err := c.ListRoutes(context.Background())
			return err
		}},
		{"remove_route", call{http.MethodDelete, "/api/v1/routes/x"}, func(c *Client) error {
			return c.RemoveRoute(context.Background(), "x")
		}},
		{"list_domains", call{http.MethodGet, "/api/v1/domains"}, func(c *Client) error {
			_, err := c.ListDomains(context.Background())
			return err
		}},
		{"select_domain", call{http.MethodPost, "/api/v1/domains/select"}, func(c *Client) error {
			_, err := c.SelectDomain(context.Background(), "r", "x", "d")
			return err
		}},
		{"status", call{http.MethodGet, "/api/v1/status"}, func(c *Client) error {
			_, err := c.Status(context.Background())
			return err
		}},
		{"update_route", call{http.MethodPost, "/api/v1/routes/update"}, func(c *Client) error {
			_, err := c.UpdateRoute(context.Background(), "x", RouteUpdate{PublicPort: 1})
			return err
		}},
		{"route_stats", call{http.MethodGet, "/api/v1/route/stats"}, func(c *Client) error {
			_, err := c.RouteStats(context.Background(), "x")
			return err
		}},
		{"list_mail_accounts", call{http.MethodGet, "/api/mail/accounts"}, func(c *Client) error {
			_, err := c.ListMailAccounts(context.Background())
			return err
		}},
		{"create_mail_account", call{http.MethodPost, "/api/mail/accounts"}, func(c *Client) error {
			_, err := c.CreateMailAccount(context.Background(), "a", "p")
			return err
		}},
		{"update_mail_password", call{http.MethodPatch, "/api/mail/accounts/a"}, func(c *Client) error {
			return c.UpdateMailAccountPassword(context.Background(), "a", "p")
		}},
		{"delete_mail_account", call{http.MethodDelete, "/api/mail/accounts/a"}, func(c *Client) error {
			return c.DeleteMailAccount(context.Background(), "a")
		}},
		{"authenticate_mail", call{http.MethodPost, "/api/mail/login"}, func(c *Client) error {
			_, err := c.AuthenticateMail(context.Background(), "a", "p")
			return err
		}},
		{"list_mail_messages", call{http.MethodPost, "/api/mail/inbox"}, func(c *Client) error {
			_, err := c.ListMailMessages(context.Background(), "a", "p")
			return err
		}},
		{"get_mail_message", call{http.MethodPost, "/api/mail/message"}, func(c *Client) error {
			_, err := c.GetMailMessage(context.Background(), "a", "p", 1)
			return err
		}},
		{"delete_mail_message", call{http.MethodPost, "/api/mail/delete"}, func(c *Client) error {
			return c.DeleteMailMessage(context.Background(), "a", "p", 1)
		}},
		{"lock_mail", call{http.MethodPost, "/api/mail/lock"}, func(c *Client) error {
			return c.LockMailService(context.Background(), true)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got call
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = call{r.Method, r.URL.Path}
				writeOKResponse(w, http.StatusOK, nil)
			}))
			defer srv.Close()

			if err := tc.do(NewClient(srv.URL)); err != nil {
				t.Fatalf("call returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// --- Content-Type header is set on bodied requests ---

func TestContentTypeHeaderOnPost(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		writeOKResponse(w, http.StatusOK, RegisterResponse{Status: "active", RouteName: "x"})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if _, err := client.Register(context.Background(), RegisterRequest{Name: "x", Proto: "tcp", LocalPort: 1}); err != nil {
		t.Fatal(err)
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotCT)
	}
}
