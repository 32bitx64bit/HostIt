package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/pbkdf2"

	"hostit/shared/netutil"
)

const (
	AlgAES128 = "aes-128"
	AlgAES256 = "aes-256"
	AlgNone   = "none"
)

func DeriveKey(token string, alg string) ([]byte, error) {
	// Derive salt from token to prevent rainbow table attacks across deployments.
	saltHash := sha256.Sum256([]byte("hostit-key-salt:" + token))
	salt := saltHash[:]

	switch strings.ToLower(alg) {
	case AlgAES128:
		return pbkdf2.Key([]byte(token), salt, 600_000, 16, sha256.New), nil
	case AlgAES256:
		return pbkdf2.Key([]byte(token), salt, 600_000, 32, sha256.New), nil
	case AlgNone, "":
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

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

// nonceBatchSize: each refill serves nonceBatchSize/12 packets, so the
// per-packet getrandom() syscall cost is amortized to ~1/341.
const nonceBatchSize = 4096

var noncePool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, nonceBatchSize)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			// rand.Reader should not fail on a healthy system. The zero
			// fallback still produces nonces that are unique across the
			// next refill, which the pool's New function will trigger.
			for i := range b {
				b[i] = 0
			}
		}
		return &b
	},
}

func fillNonceBatch(out []byte) {
	batchPtr, ok := noncePool.Get().(*[]byte)
	if !ok {
		io.ReadFull(rand.Reader, out)
		return
	}
	batch := *batchPtr
	if len(batch) < len(out) {
		// Drop the empty slice instead of returning it; the pool's New
		// function will allocate a fresh batch on the next Get.
		fillNonceBatch(out)
		return
	}
	copy(out, batch[:len(out)])
	*batchPtr = batch[len(out):]
	noncePool.Put(batchPtr)
}

func EncryptUDP(aesgcm cipher.AEAD, dst, plaintext []byte) ([]byte, error) {
	if aesgcm == nil {
		dst = dst[:0]
		return append(dst, plaintext...), nil
	}
	nonceSize := aesgcm.NonceSize()

	outLen := nonceSize + len(plaintext) + aesgcm.Overhead()
	if cap(dst) < outLen {
		dst = make([]byte, nonceSize, outLen)
	} else {
		dst = dst[:nonceSize]
	}

	batchPtr, ok := noncePool.Get().(*[]byte)
	if !ok {
		io.ReadFull(rand.Reader, dst[:nonceSize])
	} else {
		batch := *batchPtr
		if len(batch) < nonceSize {
			fillNonceBatch(dst[:nonceSize])
		} else {
			copy(dst[:nonceSize], batch[:nonceSize])
			*batchPtr = batch[nonceSize:]
			noncePool.Put(batchPtr)
		}
	}

	return aesgcm.Seal(dst, dst[:nonceSize], plaintext, nil), nil
}

// StreamCipher caches NonceSize and Overhead so the per-packet hot
// path skips two cipher.AEAD interface dispatches.
type StreamCipher struct {
	aead      cipher.AEAD
	nonceSize int
	overhead  int
}

func NewStreamCipher(aesgcm cipher.AEAD) *StreamCipher {
	if aesgcm == nil {
		return nil
	}
	return &StreamCipher{
		aead:      aesgcm,
		nonceSize: aesgcm.NonceSize(),
		overhead:  aesgcm.Overhead(),
	}
}

func (c *StreamCipher) Aead() cipher.AEAD   { return c.aead }
func (c *StreamCipher) NonceSize() int      { return c.nonceSize }
func (c *StreamCipher) Overhead() int       { return c.overhead }

func (c *StreamCipher) Encrypt(dst, plaintext []byte) ([]byte, error) {
	outLen := c.nonceSize + len(plaintext) + c.overhead
	if cap(dst) < outLen {
		dst = make([]byte, c.nonceSize, outLen)
	} else {
		dst = dst[:c.nonceSize]
	}

	batchPtr, ok := noncePool.Get().(*[]byte)
	if !ok {
		io.ReadFull(rand.Reader, dst[:c.nonceSize])
	} else {
		batch := *batchPtr
		if len(batch) < c.nonceSize {
			fillNonceBatch(dst[:c.nonceSize])
		} else {
			copy(dst[:c.nonceSize], batch[:c.nonceSize])
			*batchPtr = batch[c.nonceSize:]
			noncePool.Put(batchPtr)
		}
	}

	return c.aead.Seal(dst, dst[:c.nonceSize], plaintext, nil), nil
}

func (c *StreamCipher) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < c.nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:c.nonceSize], ciphertext[c.nonceSize:]

	outLen := len(ciphertext) - c.overhead
	if outLen < 0 {
		outLen = 0
	}
	if cap(dst) < outLen {
		dst = make([]byte, 0, outLen)
	} else {
		dst = dst[:0]
	}

	return c.aead.Open(dst, nonce, ciphertext, nil)
}

func DecryptUDP(aesgcm cipher.AEAD, dst, ciphertext []byte) ([]byte, error) {
	if aesgcm == nil {
		dst = dst[:0]
		return append(dst, ciphertext...), nil
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

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

const (
	gcmNonceSize     = 12
	maxPlaintextSize = 32 * 1024
	frameLenSize     = 2
	maxFrameBodySize = gcmNonceSize + maxPlaintextSize + 16 // nonce + ciphertext + GCM tag
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

func WrapTCP(conn net.Conn, key []byte, isClient bool) (net.Conn, error) {
	if len(key) == 0 {
		return conn, nil
	}
	block, err := aes.NewCipher(key)
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
		writeSeed: deriveSeed(key, writeLabel),
		readSeed:  deriveSeed(key, readLabel),
		readBuf:   make([]byte, 0, maxPlaintextSize),
	}, nil
}

type cryptoConn struct {
	net.Conn
	gcm        cipher.AEAD
	writeSeed  [gcmNonceSize]byte
	writeNonce uint64
	readSeed   [gcmNonceSize]byte
	readBuf    []byte
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
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		if len(c.readBuf) == 0 {
			c.readBuf = c.readBuf[:0]
		}
		return n, nil
	}

	var header [frameLenSize]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, err
	}
	frameLen := int(header[0])<<8 | int(header[1])
	if frameLen < gcmNonceSize+c.gcm.Overhead() {
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

	nonce := frame[:gcmNonceSize]
	ciphertext := frame[gcmNonceSize:]

	plaintext, err := c.gcm.Open(c.readBuf[:0], nonce, ciphertext, nil)
	readFramePool.Put(framePtr)
	if err != nil {
		return 0, fmt.Errorf("GCM decrypt failed: %w", err)
	}

	if len(plaintext) == 0 {
		c.readBuf = c.readBuf[:0]
		return c.Read(b)
	}

	n := copy(b, plaintext)
	if n < len(plaintext) {
		c.readBuf = append(c.readBuf[:0], plaintext[n:]...)
	} else {
		c.readBuf = c.readBuf[:0]
	}
	return n, nil
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

		frameBodyLen := gcmNonceSize + chunk + c.gcm.Overhead()
		buf[0] = byte(frameBodyLen >> 8)
		buf[1] = byte(frameBodyLen)
		copy(buf[frameLenSize:], nonce[:])
		c.gcm.Seal(buf[frameLenSize+gcmNonceSize:frameLenSize+gcmNonceSize], nonce[:], b[:chunk], nil)

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
