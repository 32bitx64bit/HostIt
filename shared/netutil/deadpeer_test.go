package netutil

import (
	"net"
	"testing"
	"time"
)

// tcpConnPair returns a connected client/server *net.TCPConn pair bound to the
// loopback interface. Both connections and the listener are closed via t.Cleanup.
func tcpConnPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server accept")
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func TestSetTCPUserTimeoutOnTCPConn(t *testing.T) {
	client, _ := tcpConnPair(t)
	if err := SetTCPUserTimeout(client, 5*time.Second); err != nil {
		t.Fatalf("SetTCPUserTimeout returned error: %v", err)
	}
}

func TestSetTCPUserTimeoutNonPositiveIsNoOp(t *testing.T) {
	client, _ := tcpConnPair(t)
	if err := SetTCPUserTimeout(client, 0); err != nil {
		t.Fatalf("SetTCPUserTimeout(0) returned error: %v", err)
	}
	if err := SetTCPUserTimeout(client, -time.Second); err != nil {
		t.Fatalf("SetTCPUserTimeout(-1s) returned error: %v", err)
	}
}

func TestSetTCPUserTimeoutNonTCPIsNoOp(t *testing.T) {
	if err := SetTCPUserTimeout(dummyConn{}, 5*time.Second); err != nil {
		t.Fatalf("SetTCPUserTimeout(non-tcp) returned error: %v", err)
	}
	if err := SetTCPUserTimeout(nil, 5*time.Second); err != nil {
		t.Fatalf("SetTCPUserTimeout(nil) returned error: %v", err)
	}
}

func TestSetTCPKeepAliveConfigOnTCPConn(t *testing.T) {
	client, _ := tcpConnPair(t)
	// Should not panic and should leave the connection usable.
	SetTCPKeepAliveConfig(client, 10*time.Second, 5*time.Second, 3)
	_ = client.SetDeadline(time.Now().Add(time.Second))
}

func TestSetTCPKeepAliveConfigNonTCPIsNoOp(t *testing.T) {
	// Non-TCP connections must be ignored without panicking.
	SetTCPKeepAliveConfig(dummyConn{}, 10*time.Second, 5*time.Second, 3)
	SetTCPKeepAliveConfig(nil, 10*time.Second, 5*time.Second, 3)
}

func TestTuneDeadPeerDetectionOnTCPConn(t *testing.T) {
	client, _ := tcpConnPair(t)
	// Applies keepalive + user timeout. Must not error or disturb the conn.
	TuneDeadPeerDetection(client)
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write after tuning failed: %v", err)
	}
}

func TestTuneDeadPeerDetectionThroughWrappedConn(t *testing.T) {
	client, _ := tcpConnPair(t)
	// A wrapper that exposes the underlying conn via NetConn() must still be
	// tuned (the helpers unwrap to the *net.TCPConn).
	TuneDeadPeerDetection(wrappedConn{Conn: client})
}

func TestTuneDeadPeerDetectionNonTCPIsNoOp(t *testing.T) {
	// Pipe connections are not TCP; tuning must be a silent no-op.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	TuneDeadPeerDetection(a)
	TuneDeadPeerDetection(nil)
}
