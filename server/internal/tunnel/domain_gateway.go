package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"hostit/server/internal/tlsutil"
	"hostit/shared/logging"
	"hostit/shared/protocol"
)

const (
	managedProxyResponseHeaderTimeout = 0
	managedProxyExpectContinueTimeout = 5 * time.Second
)

type managedProxyTransport struct {
	base *http.Transport
}

func (t *managedProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.base == nil {
		return nil, fmt.Errorf("managed proxy transport is not configured")
	}

	if requiresFreshTunnelConn(req) {
		t.base.CloseIdleConnections()
		clone := req.Clone(req.Context())
		clone.Close = true
		req = clone
	}

	return t.base.RoundTrip(req)
}

func (t *managedProxyTransport) CloseIdleConnections() {
	if t != nil && t.base != nil {
		t.base.CloseIdleConnections()
	}
}

func requiresFreshTunnelConn(req *http.Request) bool {
	if req == nil {
		return false
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

type domainCertManager struct {
	server      *Server
	autocert    *autocert.Manager
	renewBefore time.Duration
}

func newDomainCertManager(s *Server) *domainCertManager {
	renewBefore := s.cfg.DomainRenewBefore
	if renewBefore <= 0 {
		renewBefore = 7 * 24 * time.Hour
	}
	m := &domainCertManager{server: s, renewBefore: renewBefore}
	if s.cfg.DomainAutoTLS {
		m.autocert = &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(filepath.Join(s.cfg.DomainCertDir, "acme")),
			Email:  strings.TrimSpace(s.cfg.DomainACMEEmail),
			HostPolicy: func(_ context.Context, host string) error {
				host = normalizeHostname(host)
				if !s.isManagedDomain(host) {
					return fmt.Errorf("managed domain not configured: %s", host)
				}
				return nil
			},
		}
	}
	return m
}

func (m *domainCertManager) HTTPHandler(fallback http.Handler) http.Handler {
	if m == nil || m.autocert == nil {
		return fallback
	}
	return m.autocert.HTTPHandler(fallback)
}

func (m *domainCertManager) Run(ctx context.Context) {
	if m == nil {
		return
	}
	m.refreshAll()
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refreshAll()
		}
	}
}

func (m *domainCertManager) refreshAll() {
	for _, host := range m.server.managedDomains() {
		if err := m.ensureFresh(host); err != nil {
			logging.Global().Errorf(logging.CatEncryption, "failed to refresh managed certificate for %s: %v", host, err)
		}
	}
}

func (m *domainCertManager) ensureFresh(host string) error {
	host = normalizeHostname(host)
	if host == "" {
		return nil
	}
	if m.autocert != nil {
		_, err := m.autocert.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
		return err
	}
	_, err := m.selfSignedCertificate(host)
	return err
}

func (m *domainCertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, fmt.Errorf("client hello required")
	}
	host := normalizeHostname(hello.ServerName)
	if host == "" {
		return nil, fmt.Errorf("managed domain requires SNI server name")
	}
	if !m.server.isManagedDomain(host) {
		return nil, fmt.Errorf("managed domain not configured: %s", host)
	}
	if m.autocert != nil {
		cert, err := m.autocert.GetCertificate(hello)
		if err == nil {
			return cert, nil
		}
		logging.Global().Errorf(logging.CatEncryption, "automatic certificate fetch failed for %s: %v", host, err)
	}
	return m.selfSignedCertificate(host)
}

func (m *domainCertManager) selfSignedCertificate(host string) (*tls.Certificate, error) {
	certFile := filepath.Join(m.server.cfg.DomainCertDir, "selfsigned", host+".crt")
	keyFile := filepath.Join(m.server.cfg.DomainCertDir, "selfsigned", host+".key")
	if needsRenew, err := certNeedsRenew(certFile, m.renewBefore); err == nil && needsRenew {
		if _, err := tlsutil.RegenerateSelfSignedHost(certFile, keyFile, host); err != nil {
			return nil, err
		}
	} else {
		if _, err := tlsutil.EnsureSelfSignedHost(certFile, keyFile, host); err != nil {
			return nil, err
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	return &cert, nil
}

func certNeedsRenew(certFile string, renewBefore time.Duration) (bool, error) {
	if renewBefore <= 0 {
		return false, nil
	}
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return true, fmt.Errorf("%s: no CERTIFICATE PEM block", certFile)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false, err
	}
	return time.Until(cert.NotAfter) <= renewBefore, nil
}

func (s *Server) isManagedDomain(host string) bool {
	_, ok := s.managedRoute(host)
	return ok
}

func (s *Server) managedDomains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.cfg.Routes))
	for _, rt := range s.cfg.Routes {
		if rt.IsEnabled() && rt.IsDomainEnabled() {
			host := normalizeHostname(rt.Domain)
			if host != "" {
				out = append(out, host)
			}
		}
	}
	return out
}

func (s *Server) managedRoute(host string) (RouteConfig, bool) {
	host = normalizeHostname(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rt := range s.cfg.Routes {
		if rt.IsEnabled() && rt.IsDomainEnabled() && normalizeHostname(rt.Domain) == host {
			return rt, true
		}
	}
	return RouteConfig{}, false
}

func normalizeRequestHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return normalizeHostname(strings.Trim(host, "[]"))
	}
	return normalizeHostname(strings.Trim(hostport, "[]"))
}

func (s *Server) domainHTTPSAuthority(host string) string {
	host = normalizeHostname(host)
	if host == "" {
		return host
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(s.cfg.DomainHTTPSAddr))
	if err != nil || port == "" || port == "443" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func (s *Server) domainRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalizeRequestHost(r.Host)
		if _, ok := s.managedRoute(host); !ok {
			logging.Global().Warnf(logging.CatDashboard, "managed domain redirect miss host=%s raw_host=%s", host, r.Host)
			http.NotFound(w, r)
			return
		}
		target := "https://" + s.domainHTTPSAuthority(host) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

func (s *Server) domainProxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := normalizeRequestHost(r.Host)
		rt, ok := s.managedRoute(host)
		if !ok {
			logging.Global().Warnf(logging.CatDashboard, "managed domain proxy miss host=%s raw_host=%s", host, r.Host)
			http.NotFound(w, r)
			return
		}
		proxy := s.domainProxy(rt.Name, host)
		proxy.ServeHTTP(w, r)
	})
}

func (s *Server) domainProxy(routeName string, host string) *httputil.ReverseProxy {
	if cached, ok := s.domainProxyCache.Load(routeName); ok {
		if proxy, ok := cached.(*httputil.ReverseProxy); ok && proxy != nil {
			return proxy
		}
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dialRouteTCP(ctx, routeName)
		},
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: managedProxyResponseHeaderTimeout,
		ExpectContinueTimeout: managedProxyExpectContinueTimeout,
		ForceAttemptHTTP2:     false,
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetXForwarded()
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "tunnel-backend"
			pr.Out.Host = pr.In.Host
		},
		Transport: &managedProxyTransport{base: transport},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			transport.CloseIdleConnections()
			logging.Global().Errorf(logging.CatTCP, "managed domain proxy error host=%s route=%s: %v", host, routeName, err)
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
	}

	actual, loaded := s.domainProxyCache.LoadOrStore(routeName, proxy)
	if loaded {
		transport.CloseIdleConnections()
		if existing, ok := actual.(*httputil.ReverseProxy); ok && existing != nil {
			return existing
		}
	}
	return proxy
}

func (s *Server) closeDomainProxyIdleConnections() {
	s.domainProxyCache.Range(func(_, value any) bool {
		proxy, ok := value.(*httputil.ReverseProxy)
		if !ok || proxy == nil {
			return true
		}
		type idleCloser interface{ CloseIdleConnections() }
		if transport, ok := proxy.Transport.(idleCloser); ok && transport != nil {
			transport.CloseIdleConnections()
		}
		return true
	})
}

func (s *Server) startDomainGateway() error {
	if !s.cfg.DomainManagerEnabled {
		return nil
	}
	s.domainCerts = newDomainCertManager(s)

	httpsLn, err := net.Listen("tcp", s.cfg.DomainHTTPSAddr)
	if err != nil {
		return fmt.Errorf("managed https listen failed: %w", err)
	}
	s.domainHTTPSLn = httpsLn

	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: s.domainCerts.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
	s.domainHTTPSServer = &http.Server{
		Handler:           s.domainProxyHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig:         tlsConfig,
	}
	secureLn := tls.NewListener(httpsLn, tlsConfig)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.domainHTTPSServer.Serve(secureLn); err != nil && !errors.Is(err, http.ErrServerClosed) && s.ctx.Err() == nil {
			logging.Global().Errorf(logging.CatDashboard, "managed https server failed: %v", err)
		}
	}()

	if strings.TrimSpace(s.cfg.DomainHTTPAddr) != "" {
		httpLn, err := net.Listen("tcp", s.cfg.DomainHTTPAddr)
		if err != nil {
			_ = httpsLn.Close()
			return fmt.Errorf("managed http listen failed: %w", err)
		}
		s.domainHTTPLn = httpLn
		s.domainHTTPServer = &http.Server{
			Handler:           s.domainCerts.HTTPHandler(s.domainRedirectHandler()),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.domainHTTPServer.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) && s.ctx.Err() == nil {
				logging.Global().Errorf(logging.CatDashboard, "managed http server failed: %v", err)
			}
		}()
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.domainCerts.Run(s.ctx)
	}()

	logging.Global().Infof(logging.CatDashboard, "managed domain gateway enabled https=%s http=%s", s.cfg.DomainHTTPSAddr, s.cfg.DomainHTTPAddr)
	return nil
}

func (s *Server) dialRouteTCP(ctx context.Context, routeName string) (net.Conn, error) {
	s.mu.RLock()
	agent := s.agentTCP
	enabled := false
	for _, rt := range s.cfg.Routes {
		if rt.Name == routeName {
			enabled = rt.IsEnabled()
			break
		}
	}
	s.mu.RUnlock()
	if !enabled {
		return nil, fmt.Errorf("route %s is disabled", routeName)
	}
	if agent == nil {
		return nil, fmt.Errorf("agent not connected")
	}

	remoteAddr := agent.RemoteAddr().String()
	clientID := s.nextClientID()
	pendingKey := makePendingTCPKey(routeName, clientID)
	ch := make(chan net.Conn, 1)

	s.mu.Lock()
	s.pendingTCP[pendingKey] = ch
	s.mu.Unlock()
	cleanup := func() {
		s.mu.Lock()
		delete(s.pendingTCP, pendingKey)
		s.mu.Unlock()
	}

	reqPkt := &protocol.Packet{Type: protocol.TypeConnect, Route: routeName, Client: clientID}
	s.sessionsMu.Lock()
	session, ok := s.sessions[remoteAddr]
	if !ok {
		s.sessionsMu.Unlock()
		cleanup()
		return nil, fmt.Errorf("agent session not available")
	}
	session.writeMu.Lock()
	agent.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := protocol.WritePacket(agent, reqPkt)
	session.writeMu.Unlock()
	s.sessionsMu.Unlock()
	if err != nil {
		cleanup()
		return nil, err
	}

	timer := time.NewTimer(s.cfg.PairTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		cleanup()
		return nil, ctx.Err()
	case <-timer.C:
		cleanup()
		select {
		case lateConn := <-ch:
			if lateConn != nil {
				_ = lateConn.Close()
			}
		default:
		}
		return nil, fmt.Errorf("timeout waiting for route %s backend", routeName)
	case agentConn := <-ch:
		if agentConn == nil {
			cleanup()
			return nil, fmt.Errorf("route %s backend unavailable", routeName)
		}
		return agentConn, nil
	}
}
