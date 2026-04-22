package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hostit/shared/emailcfg"

	"golang.org/x/crypto/acme/autocert"
)

// memCache is a trivial in-memory autocert.Cache for testing.
type memCache struct {
	data map[string][]byte
}

func (c *memCache) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := c.data[key]
	if !ok {
		return nil, autocert.ErrCacheMiss
	}
	return v, nil
}
func (c *memCache) Put(_ context.Context, key string, data []byte) error {
	c.data[key] = data
	return nil
}
func (c *memCache) Delete(_ context.Context, key string) error {
	delete(c.data, key)
	return nil
}

func selfSignedPEM(host string, notAfter time.Time) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{host},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	var buf []byte
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	return buf
}

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

func TestManagedDomainCertificateFallsBackWithoutSNIForSingleDomain(t *testing.T) {
	domainEnabled := true
	srv := NewServer(ServerConfig{
		DomainManagerEnabled: true,
		DomainHTTPSAddr:      freeTCPAddr(t),
		DomainCertDir:        t.TempDir(),
		Routes: []RouteConfig{{
			Name:          "web",
			Proto:         "tcp",
			Domain:        "app.example.test",
			DomainEnabled: &domainEnabled,
		}},
	})
	mgr := newDomainCertManager(srv)
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate(no SNI) error = %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate(no SNI) returned nil cert")
	}
	if cert.Leaf == nil {
		t.Fatal("GetCertificate(no SNI) returned cert without parsed leaf")
	}
	if got := cert.Leaf.Subject.CommonName; got != "app.example.test" {
		t.Fatalf("cert common name = %q, want app.example.test", got)
	}
}

func TestManagedDomainCertificateWithoutSNIUsesFirstSortedDomain(t *testing.T) {
	domainEnabled := true
	srv := NewServer(ServerConfig{
		DomainManagerEnabled: true,
		DomainHTTPSAddr:      freeTCPAddr(t),
		DomainCertDir:        t.TempDir(),
		Routes: []RouteConfig{
			{Name: "web-1", Proto: "tcp", Domain: "app1.example.test", DomainEnabled: &domainEnabled},
			{Name: "web-2", Proto: "tcp", Domain: "app2.example.test", DomainEnabled: &domainEnabled},
		},
	})
	mgr := newDomainCertManager(srv)
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate(no SNI) error = %v, want nil", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate(no SNI) returned nil cert")
	}
	if cert.Leaf == nil {
		t.Fatal("GetCertificate(no SNI) returned cert without parsed leaf")
	}
	if got := cert.Leaf.Subject.CommonName; got != "app1.example.test" {
		t.Fatalf("cert common name = %q, want app1.example.test (first sorted domain)", got)
	}
}

func TestAcmeCertNeedsRenew_SkipsWhenCertIsValid(t *testing.T) {
	cache := &memCache{data: map[string][]byte{
		"app.example.test": selfSignedPEM("app.example.test", time.Now().Add(60*24*time.Hour)),
	}}
	mgr := &domainCertManager{
		renewBefore: 7 * 24 * time.Hour,
		autocert: &autocert.Manager{
			Cache: cache,
		},
	}
	if mgr.acmeCertNeedsRenew("app.example.test") {
		t.Fatal("acmeCertNeedsRenew = true for cert valid 60 days, want false")
	}
}

func TestAcmeCertNeedsRenew_RenewsWhenCertExpiringSoon(t *testing.T) {
	cache := &memCache{data: map[string][]byte{
		"app.example.test": selfSignedPEM("app.example.test", time.Now().Add(3*24*time.Hour)),
	}}
	mgr := &domainCertManager{
		renewBefore: 7 * 24 * time.Hour,
		autocert: &autocert.Manager{
			Cache: cache,
		},
	}
	if !mgr.acmeCertNeedsRenew("app.example.test") {
		t.Fatal("acmeCertNeedsRenew = false for cert expiring in 3 days (threshold 7), want true")
	}
}

func TestAcmeCertNeedsRenew_RenewsWhenCacheMiss(t *testing.T) {
	cache := &memCache{data: map[string][]byte{}}
	mgr := &domainCertManager{
		renewBefore: 7 * 24 * time.Hour,
		autocert: &autocert.Manager{
			Cache: cache,
		},
	}
	if !mgr.acmeCertNeedsRenew("app.example.test") {
		t.Fatal("acmeCertNeedsRenew = false for missing cert, want true")
	}
}

func TestManagedDomainEnsureFreshSkipsValidACMECert(t *testing.T) {
	cache := &memCache{data: map[string][]byte{
		"app.example.test": selfSignedPEM("app.example.test", time.Now().Add(60*24*time.Hour)),
	}}
	domainEnabled := true
	srv := NewServer(ServerConfig{
		DomainManagerEnabled: true,
		DomainHTTPSAddr:      freeTCPAddr(t),
		DomainCertDir:        t.TempDir(),
		DomainAutoTLS:        true,
		DomainACMEEmail:      "admin@example.test",
		DomainHTTPAddr:       freeTCPAddr(t),
		DomainBase:           "example.test",
		Routes: []RouteConfig{{
			Name:          "web",
			Proto:         "tcp",
			Domain:        "app.example.test",
			DomainEnabled: &domainEnabled,
		}},
	})
	mgr := newDomainCertManager(srv)
	mgr.autocert.Cache = cache

	if err := mgr.ensureFresh("app.example.test"); err != nil {
		t.Fatalf("ensureFresh() = %v, want nil (should skip renewal for valid cached cert)", err)
	}
}

func TestManagedDomainSnapshotIncludesEmailACMEHost(t *testing.T) {
	snap := buildManagedDomainSnapshot(ServerConfig{
		DomainManagerEnabled: true,
		Email: emailcfg.Config{
			Enabled:   true,
			Domain:    "example.test",
			MailHost:  "mail.example.test",
			AutoTLS:   true,
			ACMEEmail: "admin@example.test",
		},
	})
	entry, ok := snap.entries["mail.example.test"]
	if !ok {
		t.Fatal("managed domain snapshot missing email mail host")
	}
	if entry.HTTPChallengeRoute != internalEmailACMEHTTPRouteName {
		t.Fatalf("HTTPChallengeRoute = %q, want %q", entry.HTTPChallengeRoute, internalEmailACMEHTTPRouteName)
	}
	if entry.HTTPSRouteName != "" {
		t.Fatalf("HTTPSRouteName = %q, want empty for email ACME host", entry.HTTPSRouteName)
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
	if transport.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want 30s to prevent indefinite hangs on backends that accept but never respond", transport.ResponseHeaderTimeout)
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
