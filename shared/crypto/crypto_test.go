package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
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

type shortWriteConn struct {
	net.Conn
	w        *bytes.Buffer
	maxWrite int
}

func (s *shortWriteConn) Write(b []byte) (int, error) {
	if s.maxWrite > 0 && len(b) > s.maxWrite {
		b = b[:s.maxWrite]
	}
	return s.w.Write(b)
}

func TestWrapTCPLargeData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	go func() {
		c1, err := l.Accept()
		if err != nil {
			return
		}
		wc1, err := WrapTCP(c1, key)
		if err != nil {
			c1.Close()
			return
		}
		io.Copy(wc1, wc1)
	}()

	c2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	wc2, err := WrapTCP(c2, key)
	if err != nil {
		t.Fatalf("WrapTCP c2 failed: %v", err)
	}

	testSizes := []int{
		5000,
		40000,
		100000,
		500 * 1024,
	}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			payload := make([]byte, size)
			rand.Read(payload)

			wc2.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := wc2.Write(payload); err != nil {
				t.Fatalf("Write error: %v", err)
			}

			received := make([]byte, len(payload))
			wc2.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(wc2, received); err != nil {
				t.Fatalf("Read error: %v", err)
			}

			if !bytes.Equal(received, payload) {
				t.Fatalf("size %d: payload mismatch", size)
			}
		})
	}
}

func TestCryptoConnWriteHandlesShortWrites(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}

	iv := bytes.Repeat([]byte{0x42}, block.BlockSize())
	underlying := &shortWriteConn{w: &bytes.Buffer{}, maxWrite: 7}
	conn := &cryptoConn{
		Conn:   underlying,
		block:  block,
		writer: cipher.NewCTR(block, iv),
	}

	payload := bytes.Repeat([]byte("abcdef0123456789"), 128)
	if n, err := conn.Write(payload); err != nil {
		t.Fatalf("Write error: %v", err)
	} else if n != len(payload) {
		t.Fatalf("expected %d bytes written, got %d", len(payload), n)
	}

	expected := make([]byte, len(payload))
	cipher.NewCTR(block, iv).XORKeyStream(expected, payload)
	if got := underlying.w.Bytes(); !bytes.Equal(got, expected) {
		t.Fatalf("ciphertext mismatch: wrote %d bytes, expected %d", len(got), len(expected))
	}
}
