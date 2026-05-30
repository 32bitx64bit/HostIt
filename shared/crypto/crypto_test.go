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

type closeTrackingConn struct {
	net.Conn
	closed bool
}

func (c *closeTrackingConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *closeTrackingConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *closeTrackingConn) Close() error {
	c.closed = true
	return nil
}
func (c *closeTrackingConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *closeTrackingConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *closeTrackingConn) SetDeadline(time.Time) error      { return nil }
func (c *closeTrackingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeTrackingConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "tcp" }
func (d dummyAddr) String() string  { return string(d) }

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
		wc1, err1 = WrapTCP(c1, key, false)
		close(done2)
	}()
	wc2, err2 = WrapTCP(c2, key, true)
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
		wc1, err1 = WrapTCP(c1, key, false)
		close(done2)
	}()
	wc2, err2 = WrapTCP(c2, key, true)
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

// TestCryptoConnHalfClose guards the relay's half-close handshake: a wrapped
// connection must satisfy CloseWrite/CloseRead and a CloseWrite must let the
// peer drain buffered plaintext and then observe EOF (no truncation).
func TestCryptoConnHalfClose(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	rawClient, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	rawServer := <-accepted

	var wServer net.Conn
	done := make(chan struct{})
	go func() {
		wServer, _ = WrapTCP(rawServer, key, false)
		close(done)
	}()
	wClient, err := WrapTCP(rawClient, key, true)
	if err != nil {
		t.Fatalf("WrapTCP client failed: %v", err)
	}
	<-done
	defer wClient.Close()
	defer wServer.Close()

	// The relay relies on these interface assertions.
	if _, ok := wClient.(interface{ CloseWrite() error }); !ok {
		t.Fatal("cryptoConn does not implement CloseWrite")
	}
	if _, ok := wClient.(interface{ CloseRead() error }); !ok {
		t.Fatal("cryptoConn does not implement CloseRead")
	}

	payload := bytes.Repeat([]byte("half-close-payload:"), 1000)
	writeErr := make(chan error, 1)
	go func() {
		if _, err := wClient.Write(payload); err != nil {
			writeErr <- err
			return
		}
		writeErr <- wClient.(interface{ CloseWrite() error }).CloseWrite()
	}()

	_ = rawServer.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(wServer)
	if err != nil {
		t.Fatalf("ReadAll after CloseWrite failed: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write/close-write failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("peer received %d bytes, want %d (data truncated by half-close)", len(got), len(payload))
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
		wc1, err := WrapTCP(c1, key, false)
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
	wc2, err := WrapTCP(c2, key, true)
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

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}

	var seed [gcmNonceSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	underlying := &shortWriteConn{w: &bytes.Buffer{}, maxWrite: 7}
	conn := &cryptoConn{
		Conn:      underlying,
		gcm:       gcm,
		writeSeed: seed,
	}

	payload := bytes.Repeat([]byte("abcdef0123456789"), 128) // 2048 bytes
	if n, err := conn.Write(payload); err != nil {
		t.Fatalf("Write error: %v", err)
	} else if n != len(payload) {
		t.Fatalf("expected %d bytes written, got %d", len(payload), n)
	}

	// Verify by reading back frames and decrypting
	raw := underlying.w.Bytes()
	offset := 0
	var decrypted []byte
	for offset < len(raw) {
		if offset+frameLenSize > len(raw) {
			t.Fatalf("truncated frame header at offset %d", offset)
		}
		frameLen := int(raw[offset])<<8 | int(raw[offset+1])
		offset += frameLenSize
		if offset+frameLen > len(raw) {
			t.Fatalf("truncated frame body at offset %d", offset)
		}
		nonce := raw[offset : offset+gcmNonceSize]
		ciphertext := raw[offset+gcmNonceSize : offset+frameLen]
		plain, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			t.Fatalf("GCM decrypt failed at offset %d: %v", offset, err)
		}
		decrypted = append(decrypted, plain...)
		offset += frameLen
	}

	if !bytes.Equal(decrypted, payload) {
		t.Fatal("decrypted data doesn't match original payload")
	}
}

func TestCryptoConnCloseWriteFallsBackToClose(t *testing.T) {
	base := &closeTrackingConn{}
	cc := &cryptoConn{Conn: base}

	if err := cc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	if !base.closed {
		t.Fatal("CloseWrite() did not close underlying conn when half-close unsupported")
	}
}

func TestCryptoConnCloseReadFallsBackToClose(t *testing.T) {
	base := &closeTrackingConn{}
	cc := &cryptoConn{Conn: base}

	if err := cc.CloseRead(); err != nil {
		t.Fatalf("CloseRead() error = %v", err)
	}
	if !base.closed {
		t.Fatal("CloseRead() did not close underlying conn when half-close unsupported")
	}
}

func TestDeriveKeyAndUDPCipherEdgeCases(t *testing.T) {
	key128, err := DeriveKey("test-token", AlgAES128)
	if err != nil {
		t.Fatalf("DeriveKey AES-128: %v", err)
	}
	if len(key128) != 16 {
		t.Fatalf("AES-128 key length = %d, want 16", len(key128))
	}

	key256, err := DeriveKey("test-token", AlgAES256)
	if err != nil {
		t.Fatalf("DeriveKey AES-256: %v", err)
	}
	if len(key256) != 32 {
		t.Fatalf("AES-256 key length = %d, want 32", len(key256))
	}

	noKey, err := DeriveKey("test-token", AlgNone)
	if err != nil {
		t.Fatalf("DeriveKey none: %v", err)
	}
	if noKey != nil {
		t.Fatalf("DeriveKey none returned %d bytes, want nil", len(noKey))
	}

	defaultKey, err := DeriveKey("test-token", "")
	if err != nil {
		t.Fatalf("DeriveKey empty alg: %v", err)
	}
	if defaultKey != nil {
		t.Fatalf("DeriveKey empty alg returned %d bytes, want nil", len(defaultKey))
	}

	if _, err := DeriveKey("test-token", "unsupported"); err == nil {
		t.Fatal("DeriveKey unsupported algorithm error = nil")
	}

	udpCipher, err := NewUDPCipher(key128)
	if err != nil {
		t.Fatalf("NewUDPCipher valid key: %v", err)
	}
	if udpCipher == nil {
		t.Fatal("NewUDPCipher valid key = nil")
	}

	nilCipher, err := NewUDPCipher(nil)
	if err != nil {
		t.Fatalf("NewUDPCipher nil key: %v", err)
	}
	if nilCipher != nil {
		t.Fatal("NewUDPCipher nil key returned non-nil cipher")
	}

	if _, err := NewUDPCipher([]byte{1, 2, 3}); err == nil {
		t.Fatal("NewUDPCipher invalid key error = nil")
	}
}

func TestUDPEncryptDecryptEdgeCases(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	udpCipher, err := NewUDPCipher(key)
	if err != nil {
		t.Fatalf("NewUDPCipher: %v", err)
	}

	for _, plaintext := range [][]byte{[]byte("hello"), nil} {
		ciphertext, err := EncryptUDP(udpCipher, nil, plaintext)
		if err != nil {
			t.Fatalf("EncryptUDP(%q): %v", plaintext, err)
		}
		decrypted, err := DecryptUDP(udpCipher, nil, ciphertext)
		if err != nil {
			t.Fatalf("DecryptUDP(%q): %v", plaintext, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("DecryptUDP = %q, want %q", decrypted, plaintext)
		}
	}

	plaintext := []byte("plain passthrough")
	passthrough, err := EncryptUDP(nil, nil, plaintext)
	if err != nil {
		t.Fatalf("EncryptUDP nil cipher: %v", err)
	}
	if !bytes.Equal(passthrough, plaintext) {
		t.Fatalf("EncryptUDP nil cipher = %q, want %q", passthrough, plaintext)
	}
	decrypted, err := DecryptUDP(nil, nil, passthrough)
	if err != nil {
		t.Fatalf("DecryptUDP nil cipher: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptUDP nil cipher = %q, want %q", decrypted, plaintext)
	}

	if _, err := DecryptUDP(udpCipher, nil, []byte("short")); err == nil {
		t.Fatal("DecryptUDP short ciphertext error = nil")
	}

	ciphertext, err := EncryptUDP(udpCipher, nil, []byte("tamper me"))
	if err != nil {
		t.Fatalf("EncryptUDP tamper fixture: %v", err)
	}
	ciphertext[len(ciphertext)-1] ^= 0x01
	if _, err := DecryptUDP(udpCipher, nil, ciphertext); err == nil {
		t.Fatal("DecryptUDP tampered ciphertext error = nil")
	}
}

func newCryptoConnReadFixture(t *testing.T, data []byte) *cryptoConn {
	t.Helper()
	key := bytes.Repeat([]byte{1}, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return &cryptoConn{
		Conn:    &mockConn{r: bytes.NewBuffer(data), w: &bytes.Buffer{}},
		gcm:     gcm,
		readBuf: make([]byte, 0, maxPlaintextSize),
	}
}

func frameHeaderForTest(frameLen int) []byte {
	return []byte{byte(frameLen >> 8), byte(frameLen)}
}

func TestCryptoConnReadRejectsMalformedFrames(t *testing.T) {
	fixture := newCryptoConnReadFixture(t, nil)
	minimumFrameBodyLen := gcmNonceSize + fixture.gcm.Overhead()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "short header", data: []byte{0}},
		{name: "frame too short", data: frameHeaderForTest(minimumFrameBodyLen - 1)},
		{name: "frame too large", data: frameHeaderForTest(maxFrameBodySize + 1)},
		{name: "truncated body", data: append(frameHeaderForTest(minimumFrameBodyLen), bytes.Repeat([]byte{0}, minimumFrameBodyLen-1)...)},
		{name: "bad tag", data: append(frameHeaderForTest(minimumFrameBodyLen), bytes.Repeat([]byte{0}, minimumFrameBodyLen)...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newCryptoConnReadFixture(t, tt.data)
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("Read error = nil, want malformed frame error")
			}
		})
	}
}

func TestCryptoConnReadBuffersPlaintextAcrossSmallReads(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()

	client, err := WrapTCP(rawClient, key, true)
	if err != nil {
		t.Fatalf("WrapTCP client: %v", err)
	}
	server, err := WrapTCP(rawServer, key, false)
	if err != nil {
		t.Fatalf("WrapTCP server: %v", err)
	}
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("abcdef"))
		writeErrCh <- err
	}()

	first := make([]byte, 2)
	if _, err := io.ReadFull(server, first); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if string(first) != "ab" {
		t.Fatalf("first read = %q, want %q", string(first), "ab")
	}

	second := make([]byte, 4)
	if _, err := io.ReadFull(server, second); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if string(second) != "cdef" {
		t.Fatalf("second read = %q, want %q", string(second), "cdef")
	}
	if err := <-writeErrCh; err != nil {
		t.Fatalf("writer: %v", err)
	}
}
