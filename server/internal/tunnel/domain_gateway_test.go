package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func newManagedHTTPSClient(t *testing.T, dialAddr, serverName string) *http.Client {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: serverName},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, dialAddr)
			},
		},
	}
}

func waitHTTPStatus(t *testing.T, do func() (*http.Response, error), want int) *http.Response {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := do()
		if err == nil && resp != nil && resp.StatusCode == want {
			return resp
		}
		if resp != nil {
			resp.Body.Close()
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("request never succeeded: %v", err)
			}
			t.Fatalf("request never returned status %d", want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestManagedDomainHTTPSProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s path=%s", r.Host, r.URL.Path)
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	httpsAddr := freeTCPAddr(t)
	domainEnabled := true
	cfg := ServerConfig{
		ControlAddr:          controlAddr,
		DataAddr:             dataAddr,
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          10 * time.Second,
		DomainManagerEnabled: true,
		DomainHTTPSAddr:      httpsAddr,
		DomainBase:           "example.test",
		DomainCertDir:        t.TempDir(),
		Routes: []RouteConfig{{
			Name:          "web",
			Proto:         "tcp",
			LocalAddr:     backendURL.Host,
			Domain:        "app.example.test",
			DomainEnabled: &domainEnabled,
		}},
	}

	srv := NewServer(cfg)
	go func() { _ = srv.Run(ctx) }()
	go fakeAgentRoutes(ctx, controlAddr, dataAddr, map[string]string{"web": backendURL.Host}, "testtoken")

	client := newManagedHTTPSClient(t, httpsAddr, "app.example.test")
	resp := waitHTTPStatus(t, func() (*http.Response, error) {
		return client.Get("https://app.example.test/hello")
	}, http.StatusOK)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, "host=app.example.test") {
		t.Fatalf("response %q missing forwarded host", got)
	}
	if !strings.Contains(got, "path=/hello") {
		t.Fatalf("response %q missing forwarded path", got)
	}
}

func TestManagedDomainHTTPRedirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	httpAddr := freeTCPAddr(t)
	httpsAddr := freeTCPAddr(t)
	domainEnabled := true
	cfg := ServerConfig{
		ControlAddr:          controlAddr,
		DataAddr:             dataAddr,
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          10 * time.Second,
		DomainManagerEnabled: true,
		DomainHTTPAddr:       httpAddr,
		DomainHTTPSAddr:      httpsAddr,
		DomainBase:           "example.test",
		DomainCertDir:        t.TempDir(),
		Routes: []RouteConfig{{
			Name:          "web",
			Proto:         "tcp",
			LocalAddr:     backendURL.Host,
			Domain:        "app.example.test",
			DomainEnabled: &domainEnabled,
		}},
	}

	srv := NewServer(cfg)
	go func() { _ = srv.Run(ctx) }()
	go fakeAgentRoutes(ctx, controlAddr, dataAddr, map[string]string{"web": backendURL.Host}, "testtoken")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				return dialer.DialContext(ctx, network, httpAddr)
			},
		},
	}
	resp := waitHTTPStatus(t, func() (*http.Response, error) {
		return client.Get("http://app.example.test/redirect-me")
	}, http.StatusPermanentRedirect)
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if want := "https://app.example.test:" + strings.Split(httpsAddr, ":")[1] + "/redirect-me"; loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestManagedDomainHTTPSProxyReusesBackendConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var backendConnections atomic.Int32
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok:%s", r.URL.Path)
	}))
	backend.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			backendConnections.Add(1)
		}
	}
	backend.Start()
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	httpsAddr := freeTCPAddr(t)
	domainEnabled := true
	cfg := ServerConfig{
		ControlAddr:          controlAddr,
		DataAddr:             dataAddr,
		Token:                "testtoken",
		DisableTLS:           true,
		PairTimeout:          10 * time.Second,
		DomainManagerEnabled: true,
		DomainHTTPSAddr:      httpsAddr,
		DomainBase:           "example.test",
		DomainCertDir:        t.TempDir(),
		Routes: []RouteConfig{{
			Name:          "web",
			Proto:         "tcp",
			LocalAddr:     backendURL.Host,
			Domain:        "app.example.test",
			DomainEnabled: &domainEnabled,
		}},
	}

	srv := NewServer(cfg)
	go func() { _ = srv.Run(ctx) }()
	go fakeAgentRoutes(ctx, controlAddr, dataAddr, map[string]string{"web": backendURL.Host}, "testtoken")

	client := newManagedHTTPSClient(t, httpsAddr, "app.example.test")
	for _, path := range []string{"/one", "/two"} {
		resp := waitHTTPStatus(t, func() (*http.Response, error) {
			return client.Get("https://app.example.test" + path)
		}, http.StatusOK)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if got := backendConnections.Load(); got != 1 {
		t.Fatalf("backend connection count = %d, want 1 reused connection", got)
	}
}

func TestManagedDomainProxyTransportAllowsLongPosts(t *testing.T) {
	srv := NewServer(ServerConfig{})
	proxy := srv.domainProxy("web", "app.example.test")
	if proxy == nil {
		t.Fatal("domainProxy() returned nil")
	}

	managedTransport, ok := proxy.Transport.(*managedProxyTransport)
	if !ok || managedTransport == nil {
		t.Fatalf("proxy transport = %T, want *managedProxyTransport", proxy.Transport)
	}

	transport := managedTransport.base
	if !ok || transport == nil {
		t.Fatal("managed proxy transport missing base *http.Transport")
	}
	if transport.ResponseHeaderTimeout != 0 {
		t.Fatalf("ResponseHeaderTimeout = %v, want 0 so long POST handlers are not turned into 502s", transport.ResponseHeaderTimeout)
	}
	if transport.ExpectContinueTimeout != 5*time.Second {
		t.Fatalf("ExpectContinueTimeout = %v, want %v", transport.ExpectContinueTimeout, 5*time.Second)
	}
}

func TestRequiresFreshTunnelConn(t *testing.T) {
	tests := []struct {
		method string
		want   bool
	}{
		{method: http.MethodGet, want: false},
		{method: http.MethodHead, want: false},
		{method: http.MethodOptions, want: false},
		{method: http.MethodPost, want: true},
		{method: http.MethodPut, want: true},
		{method: http.MethodPatch, want: true},
		{method: http.MethodDelete, want: true},
	}

	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, "https://app.example.test/api/chat", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := requiresFreshTunnelConn(req); got != tt.want {
			t.Fatalf("requiresFreshTunnelConn(%s) = %v, want %v", tt.method, got, tt.want)
		}
	}
}

func TestManagedProxyTransportClosesIdleConnections(t *testing.T) {
	base := &http.Transport{}
	rt := &managedProxyTransport{base: base}
	rt.CloseIdleConnections()
	if rt.base != base {
		t.Fatal("CloseIdleConnections unexpectedly changed base transport")
	}
}
