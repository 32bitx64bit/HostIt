package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"hostit/shared/netutil"
)

const (
	AlgAES128 = "aes-128"
	AlgAES256 = "aes-256"
	AlgNone   = "none"
)

func DeriveKey(token string, alg string) ([]byte, error) {
	// salt derived from token prevents rainbow-table attacks across deployments
	saltHash := sha256.Sum256([]byte("hostit-key-salt:" + token))
	salt := saltHash[:]

	switch strings.ToLower(alg) {
	case AlgAES128:
		return pbkdf2.Key(sha256.New, token, salt, 600_000, 16)
	case AlgAES256:
		return pbkdf2.Key(sha256.New, token, salt, 600_000, 32)
	case AlgNone, "":
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

const (
	gcmNonceSize     = 12
	gcmTagSize       = 16
	maxPlaintextSize = 32 * 1024
	frameLenSize     = 2
	maxFrameBodySize = maxPlaintextSize + gcmTagSize // ciphertext + GCM tag
	maxFrameSize     = frameLenSize + maxFrameBodySize
)

func deriveSeed(key []byte, label string) [gcmNonceSize]byte {
	var seed [gcmNonceSize]byte
	mac := hmac.New(sha256.New, key)
	io.WriteString(mac, label)
	sum := mac.Sum(nil)
	copy(seed[:], sum)
	return seed
}

// WrapTCP returns an AES-GCM authenticated-encryption stream over conn.
// Per-session keys are derived from route key and handshake nonces.
// Nonces are counter-based and never sent on the wire.
func WrapTCP(conn net.Conn, key, clientNonce, serverNonce []byte, isClient bool) (net.Conn, error) {
	if len(key) == 0 {
		return conn, nil
	}
	info := append(clientNonce, serverNonce...)
	sessionKey, err := hkdf.Key(sha256.New, key, info, "hostit-session-key", len(key))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	writeLabel := "hostit-server-to-client"
	readLabel := "hostit-client-to-server"
	if isClient {
		writeLabel = "hostit-client-to-server"
		readLabel = "hostit-server-to-client"
	}

	return &cryptoConn{
		Conn:      conn,
		gcm:       gcm,
		writeSeed: deriveSeed(sessionKey, writeLabel),
		readSeed:  deriveSeed(sessionKey, readLabel),
		buf:       make([]byte, maxPlaintextSize),
	}, nil
}

type cryptoConn struct {
	net.Conn
	gcm        cipher.AEAD
	writeSeed  [gcmNonceSize]byte
	writeNonce uint64
	readSeed   [gcmNonceSize]byte
	readNonce  uint64
	buf        []byte
	start, end int
}

func buildNonce(seed *[gcmNonceSize]byte, counter uint64) [gcmNonceSize]byte {
	var nonce [gcmNonceSize]byte
	copy(nonce[:], seed[:])
	for i := 0; i < 8; i++ {
		nonce[i] ^= byte(counter >> (i * 8))
	}
	return nonce
}

func (c *cryptoConn) CloseRead() error {
	return netutil.CloseRead(c.Conn)
}

func (c *cryptoConn) CloseWrite() error {
	return netutil.CloseWrite(c.Conn)
}

func (c *cryptoConn) NetConn() net.Conn {
	return c.Conn
}

func (c *cryptoConn) Read(b []byte) (int, error) {
	for {
		if c.start < c.end {
			n := copy(b, c.buf[c.start:c.end])
			c.start += n
			return n, nil
		}

		var header [frameLenSize]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		frameLen := int(header[0])<<8 | int(header[1])
		if frameLen < c.gcm.Overhead() {
			return 0, errors.New("encrypted frame too short")
		}
		if frameLen > maxFrameBodySize {
			return 0, errors.New("encrypted frame too large")
		}

		framePtr := readFramePool.Get().(*[maxFrameBodySize]byte)
		frame := framePtr[:frameLen]
		if _, err := io.ReadFull(c.Conn, frame); err != nil {
			readFramePool.Put(framePtr)
			return 0, err
		}

		// counter-based nonce; replayed/reordered frames fail authentication
		nonce := buildNonce(&c.readSeed, c.readNonce)

		// reuse backing array to avoid per-frame allocations
		plaintext, err := c.gcm.Open(c.buf[:0], nonce[:], frame, nil)
		readFramePool.Put(framePtr)
		if err != nil {
			c.start = 0
			c.end = 0
			return 0, fmt.Errorf("GCM decrypt failed (tampered, replayed, or out-of-sequence frame): %w", err)
		}
		c.readNonce++

		c.start = 0
		c.end = len(plaintext)
		if c.end == 0 {
			continue
		}

		n := copy(b, c.buf[c.start:c.end])
		c.start += n
		return n, nil
	}
}

var writeBufPool = sync.Pool{
	New: func() interface{} {
		var b [maxFrameSize]byte
		return &b
	},
}

var readFramePool = sync.Pool{
	New: func() interface{} {
		var b [maxFrameBodySize]byte
		return &b
	},
}

func (c *cryptoConn) Write(b []byte) (n int, err error) {
	for len(b) > 0 {
		chunk := len(b)
		if chunk > maxPlaintextSize {
			chunk = maxPlaintextSize
		}

		nonce := buildNonce(&c.writeSeed, c.writeNonce)
		c.writeNonce++

		bufPtr := writeBufPool.Get().(*[maxFrameSize]byte)
		buf := bufPtr[:]

		frameBodyLen := chunk + c.gcm.Overhead()
		buf[0] = byte(frameBodyLen >> 8)
		buf[1] = byte(frameBodyLen)
		c.gcm.Seal(buf[frameLenSize:frameLenSize], nonce[:], b[:chunk], nil)

		totalLen := frameLenSize + frameBodyLen
		_, werr := netutil.WriteAll(c.Conn, buf[:totalLen])
		writeBufPool.Put(bufPtr)

		if werr != nil {
			return n, werr
		}
		n += chunk
		b = b[chunk:]
	}
	return n, nil
}
