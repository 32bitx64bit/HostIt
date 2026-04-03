package relay

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyPropagatesHalfClose(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()

	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		payload, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		_, _ = conn.Write(append([]byte("ack:"), payload...))
	}()

	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()

	go func() {
		frontConn, err := frontLn.Accept()
		if err != nil {
			return
		}
		backendConn, err := net.Dial("tcp", backendLn.Addr().String())
		if err != nil {
			_ = frontConn.Close()
			return
		}
		Proxy(frontConn, backendConn)
	}()

	clientConn, err := net.Dial("tcp", frontLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	clientTCP, ok := clientConn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn, got %T", clientConn)
	}

	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientConn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := clientTCP.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	resp, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "ack:hello" {
		t.Fatalf("unexpected response %q", string(resp))
	}
}
