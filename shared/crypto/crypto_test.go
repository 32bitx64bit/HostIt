package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

type mockConn struct {
	net.Conn
	r *bytes.Buffer
	w *bytes.Buffer
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.r.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return m.w.Write(b)
}

func BenchmarkCryptoConn_Write(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	var c1 net.Conn
	done := make(chan struct{})
	go func() {
		var err error
		c1, err = l.Accept()
		if err != nil {
			b.Errorf("Accept failed: %v", err)
		}
		close(done)
	}()

	c2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatalf("Dial failed: %v", err)
	}
	<-done

	var wc1, wc2 net.Conn
	var err1, err2 error
	done2 := make(chan struct{})
	go func() {
		wc1, err1 = WrapTCP(c1, key)
		close(done2)
	}()
	wc2, err2 = WrapTCP(c2, key)
	<-done2

	if err1 != nil {
		b.Fatalf("WrapTCP c1 failed: %v", err1)
	}
	if err2 != nil {
		b.Fatalf("WrapTCP c2 failed: %v", err2)
	}

	payload := make([]byte, 1024)
	rand.Read(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wc1.Write(payload)
		wc2.Read(payload)
	}
}

func TestWrapTCP(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	var c1 net.Conn
	done := make(chan struct{})
	go func() {
		var err error
		c1, err = l.Accept()
		if err != nil {
			t.Errorf("Accept failed: %v", err)
		}
		close(done)
	}()

	c2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	<-done

	var wc1, wc2 net.Conn
	var err1, err2 error
	done2 := make(chan struct{})
	go func() {
		wc1, err1 = WrapTCP(c1, key)
		close(done2)
	}()
	wc2, err2 = WrapTCP(c2, key)
	<-done2

	if err1 != nil {
		t.Fatalf("WrapTCP c1 failed: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("WrapTCP c2 failed: %v", err2)
	}

	payload := []byte("hello world")
	
	// Test write from wc1 to wc2
	if _, err := wc1.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(wc2, buf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(buf, payload) {
		t.Fatalf("Expected %q, got %q", payload, buf)
	}

	// Test write from wc2 to wc1
	if _, err := wc2.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf2 := make([]byte, len(payload))
	if _, err := io.ReadFull(wc1, buf2); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(buf2, payload) {
		t.Fatalf("Expected %q, got %q", payload, buf2)
	}
}
