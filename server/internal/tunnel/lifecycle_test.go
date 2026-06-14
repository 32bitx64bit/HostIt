package tunnel

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

func waitTunnelCondition(t *testing.T, timeout time.Duration, msg string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func dialTCPForLifecycleTest(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func dialControlForLifecycleTest(t *testing.T, controlAddr, token string) net.Conn {
	t.Helper()
	conn := dialTCPForLifecycleTest(t, controlAddr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, serverNonce, err := crypto.AuthenticateClient(conn, token)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	pub, sig := testIdentity(serverNonce)
	verPayload, _ := json.Marshal(protocol.VersionPayload{Version: protocol.ProtocolVersion, PublicKey: pub, IdentitySig: sig})
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeVersionNegotiate, Payload: verPayload}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	pkt, err := protocol.ReadPacket(conn)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if pkt.Type != protocol.TypeVersionNegotiate {
		_ = conn.Close()
		t.Fatalf("expected version negotiate, got type %d", pkt.Type)
	}
	pkt, err = protocol.ReadPacket(conn)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if pkt.Type != protocol.TypeHello {
		_ = conn.Close()
		t.Fatalf("first control packet type = %d, want HELLO", pkt.Type)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

func writeDataHandshakeForLifecycleTest(t *testing.T, conn net.Conn, routeName, clientID string) {
	t.Helper()
	if len(routeName) > 255 || len(clientID) > 255 {
		t.Fatalf("route/client too long for handshake: %d/%d", len(routeName), len(clientID))
	}
	header := make([]byte, 0, 2+len(routeName)+len(clientID))
	header = append(header, byte(len(routeName)))
	header = append(header, routeName...)
	header = append(header, byte(len(clientID)))
	header = append(header, clientID...)
	if _, err := conn.Write(header); err != nil {
		t.Fatal(err)
	}
}

func readConnectRequestForLifecycleTest(t *testing.T, conn net.Conn) *protocol.Packet {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	pkt, err := protocol.ReadPacket(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != protocol.TypeConnect {
		t.Fatalf("control packet type = %d, want CONNECT", pkt.Type)
	}
	return pkt
}

func pendingTCPCountForLifecycleTest(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pendingTCP)
}

func TestPendingTCPEntryCancelBeforeDeliveryClosesDeliveredConn(t *testing.T) {
	entry := newPendingTCPEntry()
	entry.cancel()

	select {
	case <-entry.done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not close done channel")
	}

	lateConn := newCloseTrackingConn()
	entry.deliver(lateConn)

	select {
	case <-lateConn.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("late connection delivered after cancel was not closed")
	}
	if got := entry.take(); got != nil {
		t.Fatalf("take() after cancel = %v, want nil", got)
	}
}

func TestPendingTCPEntryDuplicateDeliveryClosesSecondConn(t *testing.T) {
	entry := newPendingTCPEntry()
	first := newCloseTrackingConn()
	second := newCloseTrackingConn()

	entry.deliver(first)
	entry.deliver(second)

	select {
	case <-entry.ready:
	case <-time.After(2 * time.Second):
		t.Fatal("first delivery did not signal ready")
	}
	select {
	case <-second.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("duplicate delivery was not closed")
	}
	select {
	case <-first.closedCh:
		t.Fatal("first delivered connection was closed by duplicate delivery")
	default:
	}
	if got := entry.take(); got != first {
		t.Fatalf("take() = %v, want first delivered connection", got)
	}
}

func TestAbortPendingTCPClearsEntriesAndClosesDeliveredConns(t *testing.T) {
	srv := NewServer(ServerConfig{}, nil)
	firstEntry := newPendingTCPEntry()
	secondEntry := newPendingTCPEntry()
	delivered := newCloseTrackingConn()
	firstEntry.deliver(delivered)

	srv.mu.Lock()
	srv.pendingTCP[makePendingTCPKey("route-a", "client-a")] = firstEntry
	srv.pendingTCP[makePendingTCPKey("route-b", "client-b")] = secondEntry
	srv.abortPendingTCPLocked()
	remaining := len(srv.pendingTCP)
	srv.mu.Unlock()

	if remaining != 0 {
		t.Fatalf("pending entries remaining after abort = %d, want 0", remaining)
	}
	select {
	case <-delivered.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("delivered pending connection was not closed")
	}
	select {
	case <-secondEntry.done:
	case <-time.After(2 * time.Second):
		t.Fatal("pending entry without a delivered conn was not canceled")
	}
}

func TestDataHandshakeUnknownPairClosesConnectionWithoutPendingLeak(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       "testtoken",
		PairTimeout: time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	conn := dialTCPForLifecycleTest(t, dataAddr)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := crypto.AuthenticateClient(conn, "testtoken"); err != nil {
		t.Fatal(err)
	}
	writeDataHandshakeForLifecycleTest(t, conn, "missing-route", "client-1")

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("data connection for unknown pending pair stayed open")
	}
	waitTunnelCondition(t, 2*time.Second, "pending TCP map was not empty", func() bool {
		return pendingTCPCountForLifecycleTest(srv) == 0
	})
}

func TestPublicTCPDisabledRouteClosesWithoutConnectOrPending(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	disabled := false
	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicAddr := freeTCPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{{
			Name:       "default",
			Proto:      "tcp",
			PublicAddr: publicAddr,
			Enabled:    &disabled,
		}},
		Token:       "testtoken",
		PairTimeout: time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	agentConn := dialControlForLifecycleTest(t, controlAddr, "testtoken")
	defer agentConn.Close()

	client := dialTCPForLifecycleTest(t, publicAddr)
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("disabled route public connection stayed open")
	}

	waitTunnelCondition(t, 2*time.Second, "disabled route left pending TCP entries", func() bool {
		return pendingTCPCountForLifecycleTest(srv) == 0
	})
	_ = agentConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if pkt, err := protocol.ReadPacket(agentConn); err == nil {
		t.Fatalf("server sent CONNECT for disabled route: %#v", pkt)
	}
	_ = agentConn.SetReadDeadline(time.Time{})
}

func TestPublicTCPPairTimeoutCleansPendingAndReleasesLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicAddr := freeTCPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{{
			Name:       "default",
			Proto:      "tcp",
			PublicAddr: publicAddr,
		}},
		Token:       "testtoken",
		PairTimeout: 100 * time.Millisecond,
		DisableTLS:  true,
	}, nil)
	srv.maxConnsPerRoute = 1
	go func() { _ = srv.Run(ctx) }()

	agentConn := dialControlForLifecycleTest(t, controlAddr, "testtoken")
	defer agentConn.Close()

	firstClient := dialTCPForLifecycleTest(t, publicAddr)
	defer firstClient.Close()
	firstReq := readConnectRequestForLifecycleTest(t, agentConn)
	if firstReq.Route != "default" || firstReq.Client == "" {
		t.Fatalf("first CONNECT = route %q client %q, want default/non-empty", firstReq.Route, firstReq.Client)
	}
	_ = firstClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := firstClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("first public client stayed open after pair timeout")
	}
	waitTunnelCondition(t, 2*time.Second, "pending TCP was not cleaned after first timeout", func() bool {
		return pendingTCPCountForLifecycleTest(srv) == 0
	})

	secondClient := dialTCPForLifecycleTest(t, publicAddr)
	defer secondClient.Close()
	secondReq := readConnectRequestForLifecycleTest(t, agentConn)
	if secondReq.Route != "default" || secondReq.Client == "" || secondReq.Client == firstReq.Client {
		t.Fatalf("second CONNECT = route %q client %q, first client %q", secondReq.Route, secondReq.Client, firstReq.Client)
	}
	_ = secondClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := secondClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("second public client stayed open after pair timeout")
	}
	waitTunnelCondition(t, 2*time.Second, "pending TCP was not cleaned after second timeout", func() bool {
		return pendingTCPCountForLifecycleTest(srv) == 0
	})
}

func TestLateDataHandshakeAfterPairTimeoutIsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicAddr := freeTCPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{{
			Name:       "default",
			Proto:      "tcp",
			PublicAddr: publicAddr,
		}},
		Token:       "testtoken",
		PairTimeout: 100 * time.Millisecond,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	agentConn := dialControlForLifecycleTest(t, controlAddr, "testtoken")
	defer agentConn.Close()

	client := dialTCPForLifecycleTest(t, publicAddr)
	defer client.Close()
	req := readConnectRequestForLifecycleTest(t, agentConn)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("public client stayed open after pair timeout")
	}
	waitTunnelCondition(t, 2*time.Second, "pending TCP was not cleaned before late delivery", func() bool {
		return pendingTCPCountForLifecycleTest(srv) == 0
	})

	dataConn := dialTCPForLifecycleTest(t, dataAddr)
	defer dataConn.Close()
	_ = dataConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := crypto.AuthenticateClient(dataConn, "testtoken"); err != nil {
		t.Fatal(err)
	}
	writeDataHandshakeForLifecycleTest(t, dataConn, req.Route, req.Client)
	if _, err := dataConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("late data connection stayed open after pair timeout")
	}
}

func TestAgentDisconnectAbortsPendingPublicConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicAddr := freeTCPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{{
			Name:       "default",
			Proto:      "tcp",
			PublicAddr: publicAddr,
		}},
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	agentConn := dialControlForLifecycleTest(t, controlAddr, "testtoken")
	client := dialTCPForLifecycleTest(t, publicAddr)
	defer client.Close()
	_ = readConnectRequestForLifecycleTest(t, agentConn)
	waitTunnelCondition(t, 2*time.Second, "public connection did not create pending TCP entry", func() bool {
		return pendingTCPCountForLifecycleTest(srv) == 1
	})

	_ = agentConn.Close()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("public client stayed open after agent disconnect")
	}
	waitTunnelCondition(t, 2*time.Second, "agent disconnect did not clear pending TCP", func() bool {
		return pendingTCPCountForLifecycleTest(srv) == 0
	})
}

func TestDataHandshakeDeliveredConnPairsWithWaitingPublicClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicAddr := freeTCPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{{
			Name:       "default",
			Proto:      "tcp",
			PublicAddr: publicAddr,
		}},
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	agentConn := dialControlForLifecycleTest(t, controlAddr, "testtoken")
	defer agentConn.Close()

	publicClient := dialTCPForLifecycleTest(t, publicAddr)
	defer publicClient.Close()
	req := readConnectRequestForLifecycleTest(t, agentConn)

	dataConn := dialTCPForLifecycleTest(t, dataAddr)
	defer dataConn.Close()
	_ = dataConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := crypto.AuthenticateClient(dataConn, "testtoken"); err != nil {
		t.Fatal(err)
	}
	writeDataHandshakeForLifecycleTest(t, dataConn, req.Route, req.Client)

	publicPayload := []byte("from-public")
	dataPayload := []byte("from-agent")
	publicErrCh := make(chan error, 1)
	go func() {
		_, err := publicClient.Write(publicPayload)
		publicErrCh <- err
	}()
	dataBuf := make([]byte, len(publicPayload))
	if _, err := io.ReadFull(dataConn, dataBuf); err != nil {
		t.Fatal(err)
	}
	if err := <-publicErrCh; err != nil {
		t.Fatal(err)
	}
	if string(dataBuf) != string(publicPayload) {
		t.Fatalf("data side read %q, want %q", string(dataBuf), string(publicPayload))
	}

	dataErrCh := make(chan error, 1)
	go func() {
		_, err := dataConn.Write(dataPayload)
		dataErrCh <- err
	}()
	publicBuf := make([]byte, len(dataPayload))
	if _, err := io.ReadFull(publicClient, publicBuf); err != nil {
		t.Fatal(err)
	}
	if err := <-dataErrCh; err != nil {
		t.Fatal(err)
	}
	if string(publicBuf) != string(dataPayload) {
		t.Fatalf("public side read %q, want %q", string(publicBuf), string(dataPayload))
	}

	waitTunnelCondition(t, 2*time.Second, "pending TCP was not cleaned after delivery", func() bool {
		return pendingTCPCountForLifecycleTest(srv) == 0
	})

	_ = dataConn.Close()
	_ = publicClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := publicClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("public client stayed open after paired data connection closed")
	}
}
