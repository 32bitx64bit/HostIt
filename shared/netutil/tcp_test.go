package netutil

import (
	"net"
	"testing"
	"time"
)

type wrappedConn struct{ net.Conn }

func (w wrappedConn) NetConn() net.Conn { return w.Conn }

func TestUnwrapTCPConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	wrapped := wrappedConn{Conn: wrappedConn{Conn: client}}
	if got := UnwrapTCPConn(wrapped); got == nil {
		t.Fatal("UnwrapTCPConn() = nil, want underlying *net.TCPConn")
	}
}

func TestUnwrapTCPConnNilAndUnsupported(t *testing.T) {
	if got := UnwrapTCPConn(nil); got != nil {
		t.Fatalf("UnwrapTCPConn(nil) = %v, want nil", got)
	}
	if got := UnwrapTCPConn(dummyConn{}); got != nil {
		t.Fatalf("UnwrapTCPConn(dummyConn) = %v, want nil", got)
	}
}

type dummyConn struct{}

func (dummyConn) Read([]byte) (int, error)           { return 0, nil }
func (dummyConn) Write(b []byte) (int, error)        { return len(b), nil }
func (dummyConn) Close() error                       { return nil }
func (dummyConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (dummyConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (dummyConn) SetDeadline(_ time.Time) error      { return nil }
func (dummyConn) SetReadDeadline(_ time.Time) error  { return nil }
func (dummyConn) SetWriteDeadline(_ time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "tcp" }
func (d dummyAddr) String() string  { return string(d) }
