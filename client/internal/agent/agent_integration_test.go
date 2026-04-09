package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	sharedcrypto "hostit/shared/crypto"
	"hostit/shared/emailcfg"
	"hostit/shared/protocol"
)

type fakeTunnelServer struct {
	t              *testing.T
	token          string
	controlLn      net.Listener
	dataTCPLn      net.Listener
	dataUDPConn    *net.UDPConn
	controlConn    net.Conn
	controlReadyCh chan struct{}
	controlMu      sync.Mutex
}

func startFakeTunnelServer(t *testing.T, token string) *fakeTunnelServer {
	t.Helper()

	for attempt := 0; attempt < 20; attempt++ {
		controlLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}

		controlPort := controlLn.Addr().(*net.TCPAddr).Port
		dataAddr := fmt.Sprintf("127.0.0.1:%d", controlPort+1)

		dataTCPLn, err := net.Listen("tcp", dataAddr)
		if err != nil {
			_ = controlLn.Close()
			continue
		}

		udpAddr, err := net.ResolveUDPAddr("udp", dataAddr)
		if err != nil {
			_ = dataTCPLn.Close()
			_ = controlLn.Close()
			continue
		}
		dataUDPConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			_ = dataTCPLn.Close()
			_ = controlLn.Close()
			continue
		}

		s := &fakeTunnelServer{
			t:              t,
			token:          token,
			controlLn:      controlLn,
			dataTCPLn:      dataTCPLn,
			dataUDPConn:    dataUDPConn,
			controlReadyCh: make(chan struct{}),
		}
		go s.acceptControl()
		return s
	}

	t.Fatal("failed to allocate fake control/data listeners")
	return nil
}

func (s *fakeTunnelServer) close() {
	s.controlMu.Lock()
	if s.controlConn != nil {
		_ = s.controlConn.Close()
	}
	s.controlMu.Unlock()
	if s.dataUDPConn != nil {
		_ = s.dataUDPConn.Close()
	}
	if s.dataTCPLn != nil {
		_ = s.dataTCPLn.Close()
	}
	if s.controlLn != nil {
		_ = s.controlLn.Close()
	}
}

func (s *fakeTunnelServer) serverAddr() string {
	return s.controlLn.Addr().String()
}

func (s *fakeTunnelServer) acceptControl() {
	conn, err := s.controlLn.Accept()
	if err != nil {
		close(s.controlReadyCh)
		return
	}
	if err := sharedcrypto.AuthenticateServer(conn, s.token); err != nil {
		_ = conn.Close()
		close(s.controlReadyCh)
		return
	}

	s.controlMu.Lock()
	s.controlConn = conn
	s.controlMu.Unlock()
	close(s.controlReadyCh)
}

func (s *fakeTunnelServer) waitForControl(t *testing.T) net.Conn {
	t.Helper()
	select {
	case <-s.controlReadyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for control connection")
	}

	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	if s.controlConn == nil {
		t.Fatal("control connection was not established")
	}
	return s.controlConn
}

func (s *fakeTunnelServer) sendHello(t *testing.T, routes map[string]RemoteRoute, email ...emailcfg.Config) {
	t.Helper()
	conn := s.waitForControl(t)
	hello := helloPayload{Routes: routes}
	if len(email) > 0 {
		hello.Email = emailcfg.Normalize(email[0])
	}
	payload, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeHello, Payload: payload}); err != nil {
		t.Fatal(err)
	}
}

func TestAgentReceivesEmailConfigFromHello(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := startFakeTunnelServer(t, "testtoken")
	defer server.close()

	connectedCh := make(chan struct{}, 1)
	emailCh := make(chan emailcfg.Config, 1)
	go func() {
		_ = RunWithHooks(ctx, Config{
			Server:     server.serverAddr(),
			Token:      "testtoken",
			DisableTLS: true,
		}, &Hooks{
			OnConnected: func() {
				select {
				case connectedCh <- struct{}{}:
				default:
				}
			},
			OnEmailConfig: func(cfg emailcfg.Config) {
				select {
				case emailCh <- cfg:
				default:
				}
			},
		})
	}()

	server.sendHello(t, map[string]RemoteRoute{}, emailcfg.Config{
		Enabled:        true,
		Domain:         "example.com",
		MailHost:       "mail.example.com",
		SubmissionAddr: "127.0.0.1:587",
		IMAPAddr:       "127.0.0.1:143",
		Accounts: []emailcfg.Account{{
			Username:    "admin",
			PasswordSet: true,
			Enabled:     true,
		}},
	})

	waitForSignal(t, connectedCh, 5*time.Second, "agent never processed HELLO")

	select {
	case cfg := <-emailCh:
		if !cfg.Enabled {
			t.Fatal("Email.Enabled = false, want true")
		}
		if cfg.EffectiveMailHost() != "mail.example.com" {
			t.Fatalf("EffectiveMailHost() = %q, want mail.example.com", cfg.EffectiveMailHost())
		}
		if len(cfg.Accounts) != 1 || cfg.Accounts[0].Username != "admin" {
			t.Fatalf("Accounts = %#v, want one admin account", cfg.Accounts)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for email config hook")
	}
}

func (s *fakeTunnelServer) sendConnect(t *testing.T, routeName, clientID string) {
	t.Helper()
	conn := s.waitForControl(t)
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeConnect, Route: routeName, Client: clientID}); err != nil {
		t.Fatal(err)
	}
}

func (s *fakeTunnelServer) acceptDataConn(t *testing.T) (net.Conn, string, string) {
	t.Helper()
	if err := s.dataTCPLn.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := s.dataTCPLn.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := sharedcrypto.AuthenticateServer(conn, s.token); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}

	var routeLen byte
	if err := binary.Read(conn, binary.BigEndian, &routeLen); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	routeBytes := make([]byte, int(routeLen))
	if _, err := io.ReadFull(conn, routeBytes); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	var clientLen byte
	if err := binary.Read(conn, binary.BigEndian, &clientLen); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	clientBytes := make([]byte, int(clientLen))
	if _, err := io.ReadFull(conn, clientBytes); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	return conn, string(routeBytes), string(clientBytes)
}

func (s *fakeTunnelServer) waitForAgentUDPAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	buf := make([]byte, 65536)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := s.dataUDPConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, addr, err := s.dataUDPConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			t.Fatal(err)
		}
		pkt, err := protocol.UnmarshalUDP(buf[:n])
		if err != nil {
			continue
		}
		if pkt.Type == protocol.TypeRegister {
			return addr
		}
	}
	t.Fatal("timed out waiting for agent UDP registration")
	return nil
}

func (s *fakeTunnelServer) sendUDPToAgent(t *testing.T, agentAddr *net.UDPAddr, routeName, clientID string, payload []byte) {
	t.Helper()
	pkt := &protocol.Packet{Type: protocol.TypeData, Route: routeName, Client: clientID, Payload: payload}
	data, err := protocol.MarshalUDP(pkt, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.dataUDPConn.WriteToUDP(data, agentAddr); err != nil {
		t.Fatal(err)
	}
}

func (s *fakeTunnelServer) readUDPData(t *testing.T) *protocol.Packet {
	t.Helper()
	buf := make([]byte, 65536)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := s.dataUDPConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, _, err := s.dataUDPConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			t.Fatal(err)
		}
		pkt, err := protocol.UnmarshalUDP(buf[:n])
		if err != nil {
			continue
		}
		if pkt.Type == protocol.TypeData {
			return pkt
		}
	}
	t.Fatal("timed out waiting for UDP data from agent")
	return nil
}

func startUDPEcho(t *testing.T, prefix string) (*net.UDPConn, string) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(append([]byte(prefix), buf[:n]...), clientAddr)
		}
	}()
	return conn, conn.LocalAddr().String()
}

func waitForSignal(t *testing.T, ch <-chan struct{}, timeout time.Duration, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatal(msg)
	}
}

func TestAgentUDPRouteCacheRefreshesOnHello(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := startFakeTunnelServer(t, "testtoken")
	defer server.close()

	backend1, backend1Addr := startUDPEcho(t, "one:")
	defer backend1.Close()
	backend2, backend2Addr := startUDPEcho(t, "two:")
	defer backend2.Close()

	connectedCh := make(chan struct{}, 1)
	go func() {
		_ = RunWithHooks(ctx, Config{
			Server:     server.serverAddr(),
			Token:      "testtoken",
			DisableTLS: true,
		}, &Hooks{OnConnected: func() {
			select {
			case connectedCh <- struct{}{}:
			default:
			}
		}})
	}()

	server.sendHello(t, map[string]RemoteRoute{
		"game": {
			Name:       "game",
			Proto:      "udp",
			PublicAddr: ":47998",
			LocalAddr:  backend1Addr,
		},
	})
	waitForSignal(t, connectedCh, 5*time.Second, "agent never processed initial HELLO")

	agentUDPAddr := server.waitForAgentUDPAddr(t)

	server.sendUDPToAgent(t, agentUDPAddr, "game", "127.0.0.1:40000", []byte("ping1"))
	resp1 := server.readUDPData(t)
	if got := string(resp1.Payload); got != "one:ping1" {
		t.Fatalf("first UDP response = %q, want %q", got, "one:ping1")
	}

	server.sendHello(t, map[string]RemoteRoute{
		"game": {
			Name:       "game",
			Proto:      "udp",
			PublicAddr: ":47998",
			LocalAddr:  backend2Addr,
		},
	})
	time.Sleep(200 * time.Millisecond)

	server.sendUDPToAgent(t, agentUDPAddr, "game", "127.0.0.1:40001", []byte("ping2"))
	resp2 := server.readUDPData(t)
	if got := string(resp2.Payload); got != "two:ping2" {
		t.Fatalf("second UDP response = %q, want %q", got, "two:ping2")
	}
}

func TestAgentTCPConnectRetriesLocalDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := startFakeTunnelServer(t, "testtoken")
	defer server.close()

	backendProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backendAddr := backendProbe.Addr().String()
	_ = backendProbe.Close()

	connectedCh := make(chan struct{}, 1)
	go func() {
		_ = RunWithHooks(ctx, Config{
			Server:     server.serverAddr(),
			Token:      "testtoken",
			DisableTLS: true,
		}, &Hooks{OnConnected: func() {
			select {
			case connectedCh <- struct{}{}:
			default:
			}
		}})
	}()

	server.sendHello(t, map[string]RemoteRoute{
		"game": {
			Name:       "game",
			Proto:      "tcp",
			PublicAddr: ":47984",
			LocalAddr:  backendAddr,
		},
	})
	waitForSignal(t, connectedCh, 5*time.Second, "agent never processed HELLO")

	server.sendConnect(t, "game", "client-1")
	dataConn, routeName, clientID := server.acceptDataConn(t)
	defer dataConn.Close()
	if routeName != "game" || clientID != "client-1" {
		t.Fatalf("unexpected data metadata route=%q client=%q", routeName, clientID)
	}

	backendReady := make(chan struct{})
	go func() {
		time.Sleep(600 * time.Millisecond)
		ln, err := net.Listen("tcp", backendAddr)
		if err != nil {
			return
		}
		defer ln.Close()
		close(backendReady)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(append([]byte("ack:"), buf[:n]...))
	}()
	waitForSignal(t, backendReady, 2*time.Second, "backend listener never started")

	if err := dataConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := dataConn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("ack:hello"))
	if _, err := io.ReadFull(dataConn, buf); err != nil {
		t.Fatal(err)
	}
	if got := string(buf); got != "ack:hello" {
		t.Fatalf("TCP response = %q, want %q", got, "ack:hello")
	}
}

func TestDialMailOutboundTCPUsesReservedRelayRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := startFakeTunnelServer(t, "testtoken")
	defer server.close()

	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := DialMailOutboundTCP(ctx, Config{
			Server:     server.serverAddr(),
			Token:      "testtoken",
			DisableTLS: true,
		}, "127.0.0.1:25")
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}()

	dataConn, routeName, clientID := server.acceptDataConn(t)
	if routeName != protocol.RouteMailOutboundTCP {
		t.Fatalf("route = %q, want %q", routeName, protocol.RouteMailOutboundTCP)
	}
	if clientID != "127.0.0.1:25" {
		t.Fatalf("clientID = %q, want %q", clientID, "127.0.0.1:25")
	}

	select {
	case err := <-errCh:
		t.Fatal(err)
	case conn := <-connCh:
		defer conn.Close()
		defer dataConn.Close()
		if _, err := dataConn.Write([]byte("220 test\r\n")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len("220 test\r\n"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		if got := string(buf); got != "220 test\r\n" {
			t.Fatalf("banner = %q, want %q", got, "220 test\\r\\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for outbound relay dial")
	}
}
