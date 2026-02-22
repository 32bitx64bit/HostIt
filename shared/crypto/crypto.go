package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/pbkdf2"
)

// Supported algorithms
const (
	AlgAES128 = "aes-128"
	AlgAES256 = "aes-256"
	AlgNone   = "none"
)

// DeriveKey derives a key of the appropriate length for the given algorithm from a shared token.
// It uses PBKDF2 with HMAC-SHA256 to derive a strong key from the token.
func DeriveKey(token string, alg string) ([]byte, error) {
	switch strings.ToLower(alg) {
	case AlgAES128:
		// Use PBKDF2 to derive a 16-byte key (AES-128)
		return pbkdf2.Key([]byte(token), []byte("hostit-salt"), 4096, 16, sha256.New), nil
	case AlgAES256:
		// Use PBKDF2 to derive a 32-byte key (AES-256)
		return pbkdf2.Key([]byte(token), []byte("hostit-salt"), 4096, 32, sha256.New), nil
	case AlgNone, "":
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

// NewUDPCipher creates a new cipher.AEAD for UDP encryption.
func NewUDPCipher(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 {
		return nil, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

var udpNonceCounter uint64

func init() {
	// Initialize the nonce counter with a random value to avoid nonce reuse across restarts
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err == nil {
		udpNonceCounter = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	}
}

// EncryptUDP encrypts a UDP payload using AES-GCM.
func EncryptUDP(aesgcm cipher.AEAD, dst, plaintext []byte) ([]byte, error) {
	if aesgcm == nil {
		return append(dst, plaintext...), nil
	}
	nonceSize := aesgcm.NonceSize()

	// Ensure dst has enough capacity for nonce + ciphertext + tag
	outLen := nonceSize + len(plaintext) + aesgcm.Overhead()
	if cap(dst) < outLen {
		dst = make([]byte, nonceSize, outLen)
	} else {
		dst = dst[:nonceSize]
	}

	// Use a fast atomic counter for the nonce instead of reading from crypto/rand
	// This is safe as long as the key is rotated before the counter wraps around (2^64 packets)
	// and the counter is unique per key. For a simple tunnel, this is usually sufficient.
	// To be strictly correct across restarts, we mix in some random bytes at startup.
	val := atomic.AddUint64(&udpNonceCounter, 1)
	for i := 0; i < 8 && i < nonceSize; i++ {
		dst[i] = byte(val >> (i * 8))
	}
	return aesgcm.Seal(dst, dst[:nonceSize], plaintext, nil), nil
}

// DecryptUDP decrypts a UDP payload using AES-GCM.
func DecryptUDP(aesgcm cipher.AEAD, dst, ciphertext []byte) ([]byte, error) {
	if aesgcm == nil {
		return append(dst, ciphertext...), nil
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Ensure dst has enough capacity for plaintext
	outLen := len(ciphertext) - aesgcm.Overhead()
	if outLen < 0 {
		outLen = 0
	}
	if cap(dst) < outLen {
		dst = make([]byte, 0, outLen)
	} else {
		dst = dst[:0]
	}

	return aesgcm.Open(dst, nonce, ciphertext, nil)
}

// WrapTCP wraps a net.Conn with AES-CTR encryption/decryption.
// It exchanges IVs concurrently to avoid deadlock when both sides call WrapTCP simultaneously.
func WrapTCP(conn net.Conn, key []byte) (net.Conn, error) {
	if len(key) == 0 {
		return conn, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate our IV
	writeIV := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, writeIV); err != nil {
		return nil, err
	}

	// Write our IV immediately to avoid waiting for a full RTT during connection setup.
	if _, err := conn.Write(writeIV); err != nil {
		return nil, fmt.Errorf("IV write failed: %w", err)
	}

	streamWriter := cipher.NewCTR(block, writeIV)

	return &cryptoConn{
		Conn:   conn,
		block:  block,
		writer: streamWriter,
	}, nil
}

type cryptoConn struct {
	net.Conn
	block    cipher.Block
	reader   cipher.Stream
	writer   cipher.Stream
	readOnce sync.Once
	readErr  error
}

func (c *cryptoConn) Read(b []byte) (n int, err error) {
	c.readOnce.Do(func() {
		iv := make([]byte, c.block.BlockSize())
		if _, err := io.ReadFull(c.Conn, iv); err != nil {
			c.readErr = fmt.Errorf("IV read failed: %w", err)
			return
		}
		c.reader = cipher.NewCTR(c.block, iv)
	})
	if c.readErr != nil {
		return 0, c.readErr
	}

	n, err = c.Conn.Read(b)
	if n > 0 {
		c.reader.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

var writeBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

func (c *cryptoConn) Write(b []byte) (n int, err error) {
	// We must not modify the input buffer, so we need a temporary buffer
	// For small writes, we can use a stack-allocated buffer to avoid allocations
	if len(b) <= 4096 {
		var buf [4096]byte
		c.writer.XORKeyStream(buf[:len(b)], b)
		return c.Conn.Write(buf[:len(b)])
	}

	// For larger writes, try to use the pool
	if len(b) <= 32*1024 {
		bufPtr := writeBufPool.Get().(*[]byte)
		buf := *bufPtr
		c.writer.XORKeyStream(buf[:len(b)], b)
		n, err = c.Conn.Write(buf[:len(b)])
		writeBufPool.Put(bufPtr)
		return n, err
	}

	// For extremely large writes, allocate a new buffer
	buf := make([]byte, len(b))
	c.writer.XORKeyStream(buf, b)
	return c.Conn.Write(buf)
}
