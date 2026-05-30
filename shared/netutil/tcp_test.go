package netutil

import (
	"errors"
	"io"
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

func TestSetTCPNoDelay(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if !SetTCPNoDelay(client) {
		t.Fatal("SetTCPNoDelay(tcpConn) = false, want true")
	}
	// Works through a wrapper that exposes NetConn().
	if !SetTCPNoDelay(wrappedConn{Conn: client}) {
		t.Fatal("SetTCPNoDelay(wrapped) = false, want true")
	}
	if SetTCPNoDelay(nil) {
		t.Fatal("SetTCPNoDelay(nil) = true, want false")
	}
	if SetTCPNoDelay(dummyConn{}) {
		t.Fatal("SetTCPNoDelay(dummyConn) = true, want false")
	}
}

type chunkWriter struct {
	chunk   int
	written []byte
	failAt  int // fail once total written reaches/exceeds this (0 = never)
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	n := len(p)
	if c.chunk > 0 && n > c.chunk {
		n = c.chunk
	}
	c.written = append(c.written, p[:n]...)
	if c.failAt > 0 && len(c.written) >= c.failAt {
		return n, errors.New("boom")
	}
	return n, nil
}

func TestWriteAllDrainsPartialWrites(t *testing.T) {
	w := &chunkWriter{chunk: 1}
	payload := []byte("hello world, this is a multi-write payload")
	n, err := WriteAll(w, payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("WriteAll wrote %d bytes, want %d", n, len(payload))
	}
	if string(w.written) != string(payload) {
		t.Fatalf("WriteAll wrote %q, want %q", w.written, payload)
	}
}

func TestWriteAllPropagatesError(t *testing.T) {
	w := &chunkWriter{chunk: 4, failAt: 4}
	_, err := WriteAll(w, []byte("abcdefgh"))
	if err == nil {
		t.Fatal("WriteAll() error = nil, want non-nil")
	}
}

type zeroWriter struct{}

func (zeroWriter) Write(p []byte) (int, error) { return 0, nil }

func TestWriteAllShortWrite(t *testing.T) {
	_, err := WriteAll(zeroWriter{}, []byte("x"))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteAll() error = %v, want io.ErrShortWrite", err)
	}
}

func TestCloseWriteHalfClosesTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := CloseWrite(client); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatalf("peer read %q, want %q (and EOF after CloseWrite)", got, "ping")
	}
}

func TestCloseWriteFallsBackToClose(t *testing.T) {
	c := &closeRecorderConn{}
	if err := CloseWrite(c); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	if !c.closed {
		t.Fatal("CloseWrite() did not fall back to Close() for non-half-close conn")
	}
}

func TestCloseReadFallsBackToClose(t *testing.T) {
	c := &closeRecorderConn{}
	if err := CloseRead(c); err != nil {
		t.Fatalf("CloseRead() error = %v", err)
	}
	if !c.closed {
		t.Fatal("CloseRead() did not fall back to Close() for non-half-close conn")
	}
}

func TestCloseWriteCloseReadNil(t *testing.T) {
	if err := CloseWrite(nil); err != nil {
		t.Fatalf("CloseWrite(nil) error = %v", err)
	}
	if err := CloseRead(nil); err != nil {
		t.Fatalf("CloseRead(nil) error = %v", err)
	}
}

type closeRecorderConn struct {
	dummyConn
	closed bool
}

func (c *closeRecorderConn) Close() error {
	c.closed = true
	return nil
}

