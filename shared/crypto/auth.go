package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
)

// AuthenticateClient performs a 1-RTT mutual authentication handshake.
func AuthenticateClient(conn net.Conn, token string) error {
	clientNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientNonce); err != nil {
		return fmt.Errorf("failed to generate client nonce: %w", err)
	}

	// Send nonce and MAC
	clientMac := computeHMAC(token, clientNonce)
	buf := make([]byte, 64)
	copy(buf[:32], clientNonce)
	copy(buf[32:], clientMac)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("failed to write client auth: %w", err)
	}

	respBuf := make([]byte, 64)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return fmt.Errorf("failed to read server response: %w", err)
	}
	serverNonce := respBuf[:32]
	serverMac := respBuf[32:]

	// Verify server MAC (includes our nonce to prevent replay)
	macData := make([]byte, 0, 64)
	macData = append(macData, serverNonce...)
	macData = append(macData, clientNonce...)
	expectedServerMac := computeHMAC(token, macData)
	if !hmac.Equal(serverMac, expectedServerMac) {
		return errors.New("server authentication failed: invalid MAC")
	}

	return nil
}

// AuthenticateServer performs the server side of the mutual authentication handshake.
func AuthenticateServer(conn net.Conn, token string) error {
	buf := make([]byte, 64)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("failed to read client auth: %w", err)
	}
	clientNonce := buf[:32]
	clientMac := buf[32:]

	expectedClientMac := computeHMAC(token, clientNonce)
	if !hmac.Equal(clientMac, expectedClientMac) {
		return errors.New("client authentication failed: invalid MAC")
	}

	serverNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverNonce); err != nil {
		return fmt.Errorf("failed to generate server nonce: %w", err)
	}

	macData := make([]byte, 0, 64)
	macData = append(macData, serverNonce...)
	macData = append(macData, clientNonce...)
	serverMac := computeHMAC(token, macData)

	respBuf := make([]byte, 64)
	copy(respBuf[:32], serverNonce)
	copy(respBuf[32:], serverMac)
	if _, err := conn.Write(respBuf); err != nil {
		return fmt.Errorf("failed to write server response: %w", err)
	}

	return nil
}

func computeHMAC(token string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(data)
	return mac.Sum(nil)
}
