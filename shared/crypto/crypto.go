package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
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
	// Derive salt from token to prevent cross-deployment rainbow tables.
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
			// Abort on RNG failure; encrypting with a broken RNG is catastrophic.
			panic(err)
		}
		return &b
	},
}

func fillNonceBatch(out []byte) {
	batchPtr, ok := noncePool.Get().(*[]byte)
	if !ok {
		if _, err := io.ReadFull(rand.Reader, out); err != nil {
			panic(err)
		}
		return
	}
	batch := *batchPtr
	if len(batch) < len(out) {
		// Drop empty slice so the pool allocates fresh on next Get.
		fillNonceBatch(out)
		return
	}
	copy(out, batch[:len(out)])
	*batchPtr = batch[len(out):]
	noncePool.Put(batchPtr)
}

func sealAEAD(aead cipher.AEAD, nonceSize, overhead int, dst, plaintext []byte) ([]byte, error) {
	outLen := nonceSize + len(plaintext) + overhead
	if cap(dst) < outLen {
		dst = make([]byte, nonceSize, outLen)
	} else {
		dst = dst[:nonceSize]
	}

	batchPtr, ok := noncePool.Get().(*[]byte)
	if !ok {
		if _, err := io.ReadFull(rand.Reader, dst[:nonceSize]); err != nil {
			panic(err)
		}
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

	return aead.Seal(dst, dst[:nonceSize], plaintext, nil), nil
}

// shared AEAD decryption impl; see sealAEAD.
func openAEAD(aead cipher.AEAD, nonceSize, overhead int, dst, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	outLen := len(ciphertext) - overhead
	if outLen < 0 {
		outLen = 0
	}
	if cap(dst) < outLen {
		dst = make([]byte, 0, outLen)
	} else {
		dst = dst[:0]
	}

	return aead.Open(dst, nonce, ciphertext, nil)
}

func EncryptUDP(aesgcm cipher.AEAD, dst, plaintext []byte) ([]byte, error) {
	if aesgcm == nil {
		dst = dst[:0]
		return append(dst, plaintext...), nil
	}
	return sealAEAD(aesgcm, aesgcm.NonceSize(), aesgcm.Overhead(), dst, plaintext)
}

// Caches NonceSize/Overhead to skip two interface dispatches per packet.
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

func (c *StreamCipher) Aead() cipher.AEAD { return c.aead }
func (c *StreamCipher) NonceSize() int    { return c.nonceSize }
func (c *StreamCipher) Overhead() int     { return c.overhead }

func (c *StreamCipher) Encrypt(dst, plaintext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		dst = dst[:0]
		return append(dst, plaintext...), nil
	}
	return sealAEAD(c.aead, c.nonceSize, c.overhead, dst, plaintext)
}

func (c *StreamCipher) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		dst = dst[:0]
		return append(dst, ciphertext...), nil
	}
	return openAEAD(c.aead, c.nonceSize, c.overhead, dst, ciphertext)
}

func DecryptUDP(aesgcm cipher.AEAD, dst, ciphertext []byte) ([]byte, error) {
	if aesgcm == nil {
		dst = dst[:0]
		return append(dst, ciphertext...), nil
	}
	return openAEAD(aesgcm, aesgcm.NonceSize(), aesgcm.Overhead(), dst, ciphertext)
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

func WrapTCP(conn net.Conn, key, clientNonce, serverNonce []byte, isClient bool) (net.Conn, error) {
	if len(key) == 0 {
		return conn, nil
	}
	// Derive a per-session key from the route key and auth nonces to
	// fix AES-GCM nonce reuse across connections.
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

		// Open into the fixed backing array to avoid per-frame reallocations.
		plaintext, err := c.gcm.Open(c.buf[:0], nonce, ciphertext, nil)
		readFramePool.Put(framePtr)
		if err != nil {
			c.start = 0
			c.end = 0
			return 0, fmt.Errorf("GCM decrypt failed: %w", err)
		}

		c.start = 0
		c.end = len(plaintext)
		if c.end == 0 {
			// Avoid recursing on empty frames to prevent stack growth.
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
