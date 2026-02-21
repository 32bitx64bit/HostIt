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
)

// Supported algorithms
const (
	AlgAES128 = "aes-128"
	AlgAES256 = "aes-256"
	AlgNone   = "none"
)

// DeriveKey derives a key of the appropriate length for the given algorithm from a shared token.
func DeriveKey(token string, alg string) ([]byte, error) {
	hash := sha256.Sum256([]byte(token))
	switch strings.ToLower(alg) {
	case AlgAES128:
		return hash[:16], nil
	case AlgAES256:
		return hash[:32], nil
	case AlgNone, "":
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

// EncryptUDP encrypts a UDP payload using AES-GCM.
func EncryptUDP(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptUDP decrypts a UDP payload using AES-GCM.
func DecryptUDP(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) == 0 {
		return ciphertext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

// WrapTCP wraps a net.Conn with AES-CTR encryption/decryption.
// It writes a random IV to the connection on creation, and reads the peer's IV.
func WrapTCP(conn net.Conn, key []byte) (net.Conn, error) {
	if len(key) == 0 {
		return conn, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate and send our IV
	writeIV := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, writeIV); err != nil {
		return nil, err
	}
	if _, err := conn.Write(writeIV); err != nil {
		return nil, err
	}

	// Read peer's IV
	readIV := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(conn, readIV); err != nil {
		return nil, err
	}

	streamWriter := cipher.NewCTR(block, writeIV)
	streamReader := cipher.NewCTR(block, readIV)

	return &cryptoConn{
		Conn:   conn,
		reader: &cipher.StreamReader{S: streamReader, R: conn},
		writer: &cipher.StreamWriter{S: streamWriter, W: conn},
	}, nil
}

type cryptoConn struct {
	net.Conn
	reader io.Reader
	writer io.Writer
}

func (c *cryptoConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *cryptoConn) Write(b []byte) (n int, err error) {
	return c.writer.Write(b)
}
