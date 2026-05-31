// SPDX-License-Identifier: LGPL-3.0-only

package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func writeOKResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": data})
}

func writeErrorResponse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": "error", "message": message})
}

func TestClientRegister(t *testing.T) {
	wantName := "myapp"
	wantProto := "tcp"
	wantLocalPort := 8080

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/register" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "bad request")
			return
		}
		if req.Name != wantName || req.Proto != wantProto || req.LocalPort != wantLocalPort {
			writeErrorResponse(w, http.StatusBadRequest, "unexpected request fields")
			return
		}

		writeOKResponse(w, http.StatusOK, RegisterResponse{
			Status:     "active",
			RequestID:  "req-1",
			RouteName:  req.Name,
			PublicAddr: ":9090",
			LocalAddr:  "127.0.0.1:8080",
			Proto:      req.Proto,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	resp, err := client.Register(context.Background(), RegisterRequest{
		Name:      wantName,
		Proto:     wantProto,
		LocalPort: wantLocalPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "active" {
		t.Fatalf("Status = %q, want %q", resp.Status, "active")
	}
	if resp.RouteName != wantName {
		t.Fatalf("RouteName = %q, want %q", resp.RouteName, wantName)
	}
	if resp.PublicAddr != ":9090" {
		t.Fatalf("PublicAddr = %q, want %q", resp.PublicAddr, ":9090")
	}
}

func TestClientListRoutes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/routes" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeOKResponse(w, http.StatusOK, []Route{
			{Name: "app", Proto: "tcp", PublicAddr: ":9090", LocalAddr: "127.0.0.1:3000"},
			{Name: "api", Proto: "udp", PublicAddr: ":9091", LocalAddr: "127.0.0.1:4000"},
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	routes, err := client.ListRoutes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("len(routes) = %d, want 2", len(routes))
	}
	if routes[0].Name != "app" || routes[1].Name != "api" {
		t.Fatalf("unexpected routes: %+v", routes)
	}
}

func TestClientRemoveRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		name := r.URL.Path[len("/api/v1/routes/"):]
		if name != "myapp" {
			writeErrorResponse(w, http.StatusNotFound, "not found")
			return
		}
		writeOKResponse(w, http.StatusOK, nil)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.RemoveRoute(context.Background(), "myapp"); err != nil {
		t.Fatal(err)
	}
}

func TestClientRemoveRouteNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.RemoveRoute(context.Background(), "myapp"); err != nil {
		t.Fatal(err)
	}
}

func TestClientRemoveRouteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorResponse(w, http.StatusNotFound, "not found")
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	err := client.RemoveRoute(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing route")
	}
}

func TestClientListDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/domains" {
			http.NotFound(w, r)
			return
		}
		writeOKResponse(w, http.StatusOK, DomainsResponse{
			Base: "example.com",
			Available: []DomainOption{
				{Host: "app.example.com", Available: true},
				{Host: "api.example.com", Available: false, Reason: "taken", UsedBy: "other"},
			},
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	resp, err := client.ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Base != "example.com" {
		t.Fatalf("Base = %q, want %q", resp.Base, "example.com")
	}
	if len(resp.Available) != 2 {
		t.Fatalf("len(Available) = %d, want 2", len(resp.Available))
	}
}

func TestClientSelectDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/domains/select" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req DomainSelectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "bad request")
			return
		}
		writeOKResponse(w, http.StatusOK, RegisterResponse{
			Status:     "active",
			RouteName:  req.RouteName,
			Domain:     req.Domain,
			PublicAddr: ":9090",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	resp, err := client.SelectDomain(context.Background(), "req-1", "myapp", "myapp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "active" {
		t.Fatalf("Status = %q, want %q", resp.Status, "active")
	}
	if resp.Domain != "myapp.example.com" {
		t.Fatalf("Domain = %q, want %q", resp.Domain, "myapp.example.com")
	}
}

func TestClientStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/status" {
			http.NotFound(w, r)
			return
		}
		writeOKResponse(w, http.StatusOK, StatusResponse{
			Connected:   true,
			Server:      "tunnel.example.com",
			Version:     "1.0.0",
			RoutesCount: 3,
			DomainBase:  "example.com",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	resp, err := client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Connected {
		t.Fatal("Connected = false, want true")
	}
	if resp.RoutesCount != 3 {
		t.Fatalf("RoutesCount = %d, want 3", resp.RoutesCount)
	}
}

func TestClientNoAPIKey(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		writeOKResponse(w, http.StatusOK, StatusResponse{Connected: true})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization header = %q, want empty", gotAuth)
	}
}

func TestClientBaseURLTrailingSlash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeOKResponse(w, http.StatusOK, StatusResponse{Connected: true})
	}))
	defer srv.Close()

	client := NewClient(srv.URL + "/")
	resp, err := client.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Connected {
		t.Fatal("Connected = false, want true")
	}
}

func TestClientServerErrors(t *testing.T) {
	tests := []struct {
		name       string
		method     func(c *Client) error
		statusCode int
	}{
		{
			name: "register_500",
			method: func(c *Client) error {
				_, err := c.Register(context.Background(), RegisterRequest{Name: "x", Proto: "tcp", LocalPort: 1})
				return err
			},
			statusCode: http.StatusInternalServerError,
		},
		{
			name: "list_routes_503",
			method: func(c *Client) error {
				_, err := c.ListRoutes(context.Background())
				return err
			},
			statusCode: http.StatusServiceUnavailable,
		},
		{
			name: "list_domains_500",
			method: func(c *Client) error {
				_, err := c.ListDomains(context.Background())
				return err
			},
			statusCode: http.StatusInternalServerError,
		},
		{
			name: "select_domain_400",
			method: func(c *Client) error {
				_, err := c.SelectDomain(context.Background(), "r1", "app", "app.example.com")
				return err
			},
			statusCode: http.StatusBadRequest,
		},
		{
			name: "status_500",
			method: func(c *Client) error {
				_, err := c.Status(context.Background())
				return err
			},
			statusCode: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeErrorResponse(w, tc.statusCode, fmt.Sprintf("error %d", tc.statusCode))
			}))
			defer srv.Close()

			client := NewClient(srv.URL)
			err := tc.method(client)
			if err == nil {
				t.Fatal("expected error for server error response")
			}
		})
	}
}

func TestClientUpdateRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/routes/update" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "bad request")
			return
		}
		if req["name"] != "myapp" {
			writeErrorResponse(w, http.StatusBadRequest, "unexpected name")
			return
		}
		writeOKResponse(w, http.StatusOK, RegisterResponse{
			Status:     "updated",
			RouteName:  "myapp",
			PublicAddr: ":9091",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	resp, err := client.UpdateRoute(context.Background(), "myapp", RouteUpdate{LocalAddr: "127.0.0.1:8081"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "updated" {
		t.Fatalf("Status = %q, want %q", resp.Status, "updated")
	}
	if resp.RouteName != "myapp" {
		t.Fatalf("RouteName = %q, want %q", resp.RouteName, "myapp")
	}
}

func TestClientRouteStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/route/stats" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		name := r.URL.Query().Get("name")
		if name != "myapp" {
			writeErrorResponse(w, http.StatusNotFound, "not found")
			return
		}
		writeOKResponse(w, http.StatusOK, RouteStats{
			Name:       "myapp",
			Proto:      "tcp",
			PublicAddr: ":9090",
			LocalAddr:  "127.0.0.1:3000",
			Connected:  true,
			Source:     "dynamic",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	stats, err := client.RouteStats(context.Background(), "myapp")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Name != "myapp" {
		t.Fatalf("Name = %q, want %q", stats.Name, "myapp")
	}
	if !stats.Connected {
		t.Fatal("Connected = false, want true")
	}
}

func TestClientListMailAccounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mail/accounts" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeOKResponse(w, http.StatusOK, []MailAccount{
			{Username: "alice", Address: "alice@example.com"},
			{Username: "bob", Address: "bob@example.com"},
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	accts, err := client.ListMailAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(accts) != 2 {
		t.Fatalf("len(accts) = %d, want 2", len(accts))
	}
	if accts[0].Username != "alice" {
		t.Fatalf("Username = %q, want %q", accts[0].Username, "alice")
	}
}

func TestClientCreateMailAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mail/accounts" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "bad request")
			return
		}
		writeOKResponse(w, http.StatusCreated, MailAccount{
			Username: req["username"],
			Address:  req["username"] + "@example.com",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	acct, err := client.CreateMailAccount(context.Background(), "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if acct.Username != "alice" {
		t.Fatalf("Username = %q, want %q", acct.Username, "alice")
	}
}

func TestClientUpdateMailAccountPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mail/accounts/alice" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPatch {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeOKResponse(w, http.StatusOK, nil)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.UpdateMailAccountPassword(context.Background(), "alice", "newsecret"); err != nil {
		t.Fatal(err)
	}
}

func TestClientDeleteMailAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mail/accounts/alice" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodDelete {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeOKResponse(w, http.StatusOK, nil)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.DeleteMailAccount(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
}

func TestClientUpdateMailAccountPasswordNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.UpdateMailAccountPassword(context.Background(), "alice", "newsecret"); err != nil {
		t.Fatal(err)
	}
}

func TestClientDeleteMailAccountNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.DeleteMailAccount(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
}

func TestClientDeleteMailMessageNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.DeleteMailMessage(context.Background(), "alice", "secret", 42); err != nil {
		t.Fatal(err)
	}
}

func TestClientListMailMessages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mail/inbox" {
			http.NotFound(w, r)
			return
		}
		writeOKResponse(w, http.StatusOK, []MailMessage{
			{ID: 1, From: "a@example.com", Subject: "Hello"},
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	msgs, err := client.ListMailMessages(context.Background(), "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Subject != "Hello" {
		t.Fatalf("unexpected messages: %+v", msgs)
	}
}

func TestClientGetMailMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mail/message" {
			http.NotFound(w, r)
			return
		}
		writeOKResponse(w, http.StatusOK, MailMessageFull{
			MailMessage: MailMessage{ID: 1, Subject: "Hi"},
			Body:        "body text",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	msg, err := client.GetMailMessage(context.Background(), "alice", "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Body != "body text" {
		t.Fatalf("Body = %q, want %q", msg.Body, "body text")
	}
}

func TestClientAuthenticateMail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mail/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "bad request")
			return
		}
		if req["username"] != "alice" || req["password"] != "secret" {
			writeErrorResponse(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeOKResponse(w, http.StatusOK, map[string]string{
			"username": req["username"],
			"address":  "alice@example.com",
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	addr, err := client.AuthenticateMail(context.Background(), "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "alice@example.com" {
		t.Fatalf("address = %q, want %q", addr, "alice@example.com")
	}
}

func TestClientEventsURL(t *testing.T) {
	tests := []struct {
		baseURL string
		want    string
	}{
		{"http://localhost:8080", "ws://localhost:8080/api/v1/events"},
		{"http://10.0.0.1:3000", "ws://10.0.0.1:3000/api/v1/events"},
	}

	for _, tc := range tests {
		client := NewClient(tc.baseURL)
		got := client.EventsURL()
		if got != tc.want {
			t.Fatalf("EventsURL() = %q, want %q", got, tc.want)
		}
	}
}

func TestClientUpdateRouteInvalidLocalAddr(t *testing.T) {
	client := NewClient("http://localhost:8080")
	_, err := client.UpdateRoute(context.Background(), "myapp", RouteUpdate{LocalAddr: "not-a-valid-addr"})
	if err == nil {
		t.Fatal("expected error for invalid LocalAddr")
	}
}

func TestClientLockMailService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mail/lock" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			writeErrorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req map[string]bool
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "bad request")
			return
		}
		writeOKResponse(w, http.StatusOK, map[string]any{
			"locked":  req["locked"],
			"enabled": false,
		})
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	if err := client.LockMailService(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := client.LockMailService(context.Background(), false); err != nil {
		t.Fatal(err)
	}
}
