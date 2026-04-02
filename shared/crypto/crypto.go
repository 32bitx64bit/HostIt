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
	switch strings.ToLower(alg) {
	case AlgAES128:
		return pbkdf2.Key([]byte(token), []byte("hostit-salt"), 4096, 16, sha256.New), nil
	case AlgAES256:
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
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err == nil {
		udpNonceCounter = uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	}
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

	val := atomic.AddUint64(&udpNonceCounter, 1)
	for i := 0; i < 8 && i < nonceSize; i++ {
		dst[i] = byte(val >> (i * 8))
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

func WrapTCP(conn net.Conn, key []byte) (net.Conn, error) {
	if len(key) == 0 {
		return conn, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	writeIV := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, writeIV); err != nil {
		return nil, err
	}

	if _, err := writeAll(conn, writeIV); err != nil {
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

func (c *cryptoConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *cryptoConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
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
		var b [32 * 1024]byte
		return &b
	},
}

func (c *cryptoConn) Write(b []byte) (n int, err error) {
	for len(b) > 0 {
		chunk := len(b)
		switch {
		case chunk <= 4096:
			var buf [4096]byte
			c.writer.XORKeyStream(buf[:chunk], b[:chunk])
			wn, werr := writeAll(c.Conn, buf[:chunk])
			n += wn
			if werr != nil {
				return n, werr
			}
		case chunk <= 32*1024:
			bufPtr := writeBufPool.Get().(*[32 * 1024]byte)
			buf := bufPtr[:]
			c.writer.XORKeyStream(buf[:chunk], b[:chunk])
			wn, werr := writeAll(c.Conn, buf[:chunk])
			writeBufPool.Put(bufPtr)
			n += wn
			if werr != nil {
				return n, werr
			}
		default:
			chunk = 32 * 1024
			bufPtr := writeBufPool.Get().(*[32 * 1024]byte)
			buf := bufPtr[:]
			c.writer.XORKeyStream(buf[:chunk], b[:chunk])
			wn, werr := writeAll(c.Conn, buf[:chunk])
			writeBufPool.Put(bufPtr)
			n += wn
			if werr != nil {
				return n, werr
			}
		}
		b = b[chunk:]
	}
	return n, nil
}
