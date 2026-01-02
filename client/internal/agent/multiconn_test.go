package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func newSelfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

func listenControlAndDataPair(t *testing.T) (controlLn net.Listener, dataLn net.Listener) {
	t.Helper()
	for i := 0; i < 50; i++ {
		ln0, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := ln0.Addr().(*net.TCPAddr).Port
		_ = ln0.Close()

		cln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			continue
		}
		dln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p+1)))
		if err != nil {
			_ = cln.Close()
			continue
		}
		return cln, dln
	}
	t.Fatalf("failed to find free control/data port pair")
	return nil, nil
}

type fakeControlServer struct {
	ln        net.Listener
	dataTLS   string
	dataInsec string
	routes    []string
	connMu    sync.Mutex
	conn      net.Conn
	writeMu   sync.Mutex
	accepted  chan struct{}
	handshake chan error
	done      chan struct{}
	closeOnce sync.Once
}

func newFakeControlServer(t *testing.T, ln net.Listener, dataTLS string, dataInsecure string, routes []string) *fakeControlServer {
	t.Helper()
	return &fakeControlServer{
		ln:       ln,
		dataTLS:  dataTLS,
		dataInsec: dataInsecure,
		routes:   routes,
		accepted: make(chan struct{}),
		handshake: make(chan error, 1),
		done:     make(chan struct{}),
	}
}

func (s *fakeControlServer) run(ctx context.Context, t *testing.T, token string) {
	t.Helper()
	defer close(s.done)

	c, err := s.ln.Accept()
	if err != nil {
		return
	}
	s.connMu.Lock()
	s.conn = c
	s.connMu.Unlock()
	close(s.accepted)
	defer c.Close()

	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		s.handshake <- err
		return
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 2 || fields[0] != "HELLO" || fields[1] != token {
		s.handshake <- fmt.Errorf("expected HELLO %s, got %q", token, strings.TrimSpace(line))
		return
	}
	s.handshake <- nil
	// OK <dataTLS> <dataInsecure>
	// Use "-" or empty to omit the insecure address.
	_, _ = io.WriteString(c, fmt.Sprintf("OK %s %s\n", s.dataTLS, s.dataInsec))
	for _, rt := range s.routes {
		_, _ = io.WriteString(c, rt+"\n")
	}
	_, _ = io.WriteString(c, "READY\n")

	<-ctx.Done()
	// Force the agent out of its ReadLine loop promptly.
	_ = c.Close()
}

func (s *fakeControlServer) sendNEW(id string, route string) error {
	s.connMu.Lock()
	c := s.conn
	s.connMu.Unlock()
	if c == nil {
		return fmt.Errorf("control conn not established")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := io.WriteString(c, fmt.Sprintf("NEW %s %s\n", id, route))
	return err
}

type fakeDataServer struct {
	ln net.Listener

	mu    sync.Mutex
	expect map[string][]byte
	resCh  chan error
}

func newFakeDataServer(t *testing.T, ln net.Listener) *fakeDataServer {
	t.Helper()
	return &fakeDataServer{
		ln:     ln,
		expect: map[string][]byte{},
		resCh:  make(chan error, 1024),
	}
}

func (s *fakeDataServer) setExpected(id string, payload []byte) {
	s.mu.Lock()
	s.expect[id] = payload
	s.mu.Unlock()
}

func (s *fakeDataServer) run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c)
	}
}

func (s *fakeDataServer) handleConn(c net.Conn) {
	defer c.Close()
	// The real server allows a while for the first CONN line. Preconnect pools may
	// create idle connections that won't send CONN until used.
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		// Ignore idle connections (e.g. preconnect warmups) that never get used.
		return
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "CONN ") {
		// Ignore any non-CONN first lines; the production server would close.
		return
	}
	id := strings.TrimSpace(strings.TrimPrefix(line, "CONN "))

	s.mu.Lock()
	payload, ok := s.expect[id]
	delete(s.expect, id)
	s.mu.Unlock()
	if !ok {
		s.resCh <- fmt.Errorf("unexpected id %q", id)
		return
	}

	if _, err := c.Write(payload); err != nil {
		s.resCh <- err
		return
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(r, buf); err != nil {
		s.resCh <- err
		return
	}
	if string(buf) != string(payload) {
		s.resCh <- fmt.Errorf("id %s: expected %q got %q", id, string(payload), string(buf))
		return
	}
	s.resCh <- nil
}

func TestAgentMultiConn_Concurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Backend echo server (agent dials 127.0.0.1:<publicPort>)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	controlLn, dataLn := listenControlAndDataPair(t)
	defer controlLn.Close()
	defer dataLn.Close()

	dataAddr := dataLn.Addr().String()

	// Route PublicAddr port must match backend port.
	publicAddr := echoLn.Addr().String()
	routes := []string{
		fmt.Sprintf("ROUTE default tcp %s preconnect=8 nodelay=1 tls=0", publicAddr),
		fmt.Sprintf("ROUTE alt tcp %s preconnect=0 nodelay=1 tls=0", publicAddr),
	}

	ctrl := newFakeControlServer(t, controlLn, dataAddr, dataAddr, routes)
	data := newFakeDataServer(t, dataLn)
	go ctrl.run(ctx, t, "testtoken")
	go data.run(ctx)

	cfg := Config{Server: controlLn.Addr().String(), Token: "testtoken", DisableTLS: true}

	agentDone := make(chan error, 1)
	go func() { agentDone <- runOnce(ctx, cfg, nil) }()

	select {
	case <-ctrl.accepted:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent never connected to control")
	}
	select {
	case err := <-ctrl.handshake:
		if err != nil {
			t.Fatalf("control handshake failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for control handshake")
	}

	const n = 20
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("id-%d", i)
		payload := []byte("hello-" + id + "\n")
		data.setExpected(id, payload)
		route := "default"
		if i%2 == 1 {
			route = "alt"
		}
		if err := ctrl.sendNEW(id, route); err != nil {
			t.Fatalf("send NEW: %v", err)
		}
	}

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for i := 0; i < n; i++ {
		select {
		case err := <-data.resCh:
			if err != nil {
				t.Fatalf("data exchange failed: %v", err)
			}
		case <-deadline.C:
			t.Fatalf("timeout waiting for %d/%d conns", i, n)
		}
	}

	cancel()
	select {
	case <-agentDone:
	case <-time.After(2 * time.Second):
		// If this hangs, the control conn wasn't closed.
		t.Fatalf("agent did not shut down")
	}
}

func TestAgentMultiConn_ReconnectLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	controlLn, dataLn := listenControlAndDataPair(t)
	defer controlLn.Close()
	defer dataLn.Close()

	dataAddr := dataLn.Addr().String()
	publicAddr := echoLn.Addr().String()
	routes := []string{fmt.Sprintf("ROUTE default tcp %s preconnect=4 nodelay=1 tls=0", publicAddr)}

	ctrl := newFakeControlServer(t, controlLn, dataAddr, dataAddr, routes)
	data := newFakeDataServer(t, dataLn)
	go ctrl.run(ctx, t, "testtoken")
	go data.run(ctx)

	cfg := Config{Server: controlLn.Addr().String(), Token: "testtoken", DisableTLS: true}

	agentDone := make(chan error, 1)
	go func() { agentDone <- runOnce(ctx, cfg, nil) }()

	select {
	case <-ctrl.accepted:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent never connected to control")
	}
	select {
	case err := <-ctrl.handshake:
		if err != nil {
			t.Fatalf("control handshake failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for control handshake")
	}

	for i := 0; i < 10; i++ {
		id := fmt.Sprintf("loop-%d", i)
		payload := []byte("ping-" + id + "\n")
		data.setExpected(id, payload)
		if err := ctrl.sendNEW(id, "default"); err != nil {
			t.Fatalf("send NEW: %v", err)
		}
		select {
		case err := <-data.resCh:
			if err != nil {
				t.Fatalf("iter %d: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iter %d: timeout", i)
		}
		// simulate client disconnect / brief idle
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case <-agentDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent did not shut down")
	}
}

func TestAgentMultiConn_TLS_Concurrent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	controlLn, dataLn := listenControlAndDataPair(t)
	defer controlLn.Close()
	defer dataLn.Close()

	tlsCfg := newSelfSignedTLSConfig(t)
	controlTLSLn := tls.NewListener(controlLn, tlsCfg)
	dataTLSLn := tls.NewListener(dataLn, tlsCfg)
	defer controlTLSLn.Close()
	defer dataTLSLn.Close()

	dataAddr := dataLn.Addr().String()
	publicAddr := echoLn.Addr().String()
	routes := []string{fmt.Sprintf("ROUTE default tcp %s preconnect=8 nodelay=1 tls=1", publicAddr)}

	ctrl := newFakeControlServer(t, controlTLSLn, dataAddr, dataAddr, routes)
	data := newFakeDataServer(t, dataTLSLn)
	go ctrl.run(ctx, t, "testtoken")
	go data.run(ctx)

	// DisableTLS=false -> control+data use TLS.
	cfg := Config{Server: controlLn.Addr().String(), Token: "testtoken", DisableTLS: false}
	agentDone := make(chan error, 1)
	go func() { agentDone <- runOnce(ctx, cfg, nil) }()

	select {
	case <-ctrl.accepted:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent never connected to control")
	}
	select {
	case err := <-ctrl.handshake:
		if err != nil {
			t.Fatalf("control handshake failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for control handshake")
	}

	const n = 50
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("tls-id-%d", i)
		payload := []byte("hello-" + id + "\n")
		data.setExpected(id, payload)
		if err := ctrl.sendNEW(id, "default"); err != nil {
			t.Fatalf("send NEW: %v", err)
		}
	}

	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	for i := 0; i < n; i++ {
		select {
		case err := <-data.resCh:
			if err != nil {
				t.Fatalf("data exchange failed: %v", err)
			}
		case <-deadline.C:
			t.Fatalf("timeout waiting for %d/%d tls conns", i, n)
		}
	}

	cancel()
	select {
	case <-agentDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent did not shut down")
	}
}

func TestAgentMultiConn_TLS_DataOnlyAdvertised(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	controlLn, dataLn := listenControlAndDataPair(t)
	defer controlLn.Close()
	defer dataLn.Close()

	tlsCfg := newSelfSignedTLSConfig(t)
	controlTLSLn := tls.NewListener(controlLn, tlsCfg)
	dataTLSLn := tls.NewListener(dataLn, tlsCfg)
	defer controlTLSLn.Close()
	defer dataTLSLn.Close()

	dataAddr := dataLn.Addr().String()
	publicAddr := echoLn.Addr().String()
	routes := []string{fmt.Sprintf("ROUTE default tcp %s preconnect=0 nodelay=1 tls=1", publicAddr)}

	ctrl := newFakeControlServer(t, controlTLSLn, dataAddr, "-", routes)
	data := newFakeDataServer(t, dataTLSLn)
	go ctrl.run(ctx, t, "testtoken")
	go data.run(ctx)

	cfg := Config{Server: controlLn.Addr().String(), Token: "testtoken", DisableTLS: false}
	agentDone := make(chan error, 1)
	go func() { agentDone <- runOnce(ctx, cfg, nil) }()

	select {
	case <-ctrl.accepted:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent never connected to control")
	}
	// If the handshake succeeds, we can proceed; data channel will use TLS regardless.
	select {
	case err := <-ctrl.handshake:
		if err != nil {
			t.Fatalf("control handshake failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for control handshake")
	}

	// Send a few NEWs and validate TLS data CONN.
	const n = 10
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("tls-only-%d", i)
		payload := []byte("hello-" + id + "\n")
		data.setExpected(id, payload)
		if err := ctrl.sendNEW(id, "default"); err != nil {
			t.Fatalf("send NEW: %v", err)
		}
	}

	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for i := 0; i < n; i++ {
		select {
		case err := <-data.resCh:
			if err != nil {
				t.Fatalf("data exchange failed: %v", err)
			}
		case <-deadline.C:
			t.Fatalf("timeout waiting for %d/%d tls-only conns", i, n)
		}
	}

	cancel()
	select {
	case <-agentDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("agent did not shut down")
	}
}
