package relay

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type relayCloseTrackingConn struct {
	mu       sync.Mutex
	closed   bool
	closedCh chan struct{}
}

func newRelayCloseTrackingConn() *relayCloseTrackingConn {
	return &relayCloseTrackingConn{closedCh: make(chan struct{})}
}

func (c *relayCloseTrackingConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *relayCloseTrackingConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *relayCloseTrackingConn) LocalAddr() net.Addr         { return relayDummyAddr("local") }
func (c *relayCloseTrackingConn) RemoteAddr() net.Addr        { return relayDummyAddr("remote") }
func (c *relayCloseTrackingConn) SetDeadline(time.Time) error { return nil }
func (c *relayCloseTrackingConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *relayCloseTrackingConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *relayCloseTrackingConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.closedCh)
	return nil
}

type relayDummyAddr string

func (d relayDummyAddr) Network() string { return "tcp" }
func (d relayDummyAddr) String() string  { return string(d) }

func waitRelayClosed(t *testing.T, conn *relayCloseTrackingConn, name string) {
	t.Helper()
	select {
	case <-conn.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s was not closed", name)
	}
}

func TestProxyNilInputClosesProvidedConn(t *testing.T) {
	conn := newRelayCloseTrackingConn()

	ProxyWithIdleTimeout(conn, nil, 0)

	waitRelayClosed(t, conn, "non-nil connection")
}

func TestProxyClosesBothWhenHalfCloseUnavailable(t *testing.T) {
	a := newRelayCloseTrackingConn()
	b := newRelayCloseTrackingConn()

	done := make(chan struct{})
	go func() {
		defer close(done)
		Proxy(a, b)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Proxy did not return after both sides reached EOF")
	}
	waitRelayClosed(t, a, "first connection")
	waitRelayClosed(t, b, "second connection")
}

func TestProxyRelaysBidirectionalData(t *testing.T) {
	client, proxyClient := net.Pipe()
	proxyBackend, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		Proxy(proxyClient, proxyBackend)
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = backend.SetDeadline(time.Now().Add(5 * time.Second))

	clientPayload := bytes.Repeat([]byte("client-to-backend:"), 4096)
	writeErrCh := make(chan error, 1)
	go func() {
		_, err := client.Write(clientPayload)
		writeErrCh <- err
	}()

	backendBuf := make([]byte, len(clientPayload))
	if _, err := io.ReadFull(backend, backendBuf); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backendBuf, clientPayload) {
		t.Fatal("backend received different bytes than the client sent")
	}

	backendPayload := bytes.Repeat([]byte("backend-to-client:"), 4096)
	go func() {
		_, err := backend.Write(backendPayload)
		writeErrCh <- err
	}()

	clientBuf := make([]byte, len(backendPayload))
	if _, err := io.ReadFull(client, clientBuf); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientBuf, backendPayload) {
		t.Fatal("client received different bytes than the backend sent")
	}

	_ = client.Close()
	_ = backend.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Proxy did not return after both endpoints closed")
	}
}

func TestProxyWithIdleTimeout(t *testing.T) {
	a, b := net.Pipe()

	idleTimeout := 100 * time.Millisecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		ProxyWithIdleTimeout(a, b, idleTimeout)
	}()

	_ = a.SetDeadline(time.Now().Add(2 * time.Second))
	_ = b.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := a.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("unexpected data: %q", string(buf))
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ProxyWithIdleTimeout did not close connections after idle timeout")
	}
}

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
