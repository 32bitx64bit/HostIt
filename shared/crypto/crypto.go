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

// EncryptUDP encrypts a UDP payload using AES-GCM.
func EncryptUDP(aesgcm cipher.AEAD, plaintext []byte) ([]byte, error) {
	if aesgcm == nil {
		return plaintext, nil
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptUDP decrypts a UDP payload using AES-GCM.
func DecryptUDP(aesgcm cipher.AEAD, ciphertext []byte) ([]byte, error) {
	if aesgcm == nil {
		return ciphertext, nil
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
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

	// Exchange IVs concurrently to avoid deadlock
	// Both sides must be able to write and read simultaneously
	var readIV []byte
	var readErr, writeErr error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		iv := make([]byte, block.BlockSize())
		_, readErr = io.ReadFull(conn, iv)
		readIV = iv
	}()
	go func() {
		defer wg.Done()
		_, writeErr = conn.Write(writeIV)
	}()
	wg.Wait()

	if readErr != nil {
		return nil, fmt.Errorf("IV read failed: %w", readErr)
	}
	if writeErr != nil {
		return nil, fmt.Errorf("IV write failed: %w", writeErr)
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
