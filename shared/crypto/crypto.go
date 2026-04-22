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
)

func writeAll(w io.Writer, b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > 0 {
			total += n
			b = b[n:]
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

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

	if _, err := io.ReadFull(rand.Reader, dst[:nonceSize]); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}
	return aesgcm.Seal(dst, dst[:nonceSize], plaintext, nil), nil
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
	mac.Write([]byte(label))
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
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	type netConner interface{ NetConn() net.Conn }
	if wrapped, ok := c.Conn.(netConner); ok {
		if nc := wrapped.NetConn(); nc != nil && nc != c.Conn {
			if cr, ok := nc.(interface{ CloseRead() error }); ok {
				return cr.CloseRead()
			}
		}
	}
	return c.Conn.Close()
}

func (c *cryptoConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	type netConner interface{ NetConn() net.Conn }
	if wrapped, ok := c.Conn.(netConner); ok {
		if nc := wrapped.NetConn(); nc != nil && nc != c.Conn {
			if cw, ok := nc.(interface{ CloseWrite() error }); ok {
				return cw.CloseWrite()
			}
		}
	}
	return c.Conn.Close()
}

func (c *cryptoConn) NetConn() net.Conn {
	return c.Conn
}

func (c *cryptoConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		if len(c.readBuf) == 0 {
			c.readBuf = nil
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

	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return 0, err
	}

	nonce := frame[:gcmNonceSize]
	ciphertext := frame[gcmNonceSize:]

	plaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("GCM decrypt failed: %w", err)
	}

	n := copy(b, plaintext)
	if n < len(plaintext) {
		c.readBuf = plaintext[n:]
	}
	return n, nil
}

var writeBufPool = sync.Pool{
	New: func() interface{} {
		var b [maxFrameSize]byte
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
		_, werr := writeAll(c.Conn, buf[:totalLen])
		writeBufPool.Put(bufPtr)

		if werr != nil {
			return n, werr
		}
		n += chunk
		b = b[chunk:]
	}
	return n, nil
}
