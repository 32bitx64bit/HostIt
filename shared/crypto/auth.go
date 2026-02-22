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

// AuthenticateClient performs the client side of the mutual authentication handshake.
// It proves to the server that the client knows the token, and verifies that the server knows it too.
// It does this in a single RTT to minimize latency.
func AuthenticateClient(conn net.Conn, token string) error {
	// 1. Generate ClientNonce (32 bytes)
	clientNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientNonce); err != nil {
		return fmt.Errorf("failed to generate client nonce: %w", err)
	}

	// 2. Send ClientNonce + ClientMac(Token, ClientNonce)
	// We send our MAC immediately so the server can verify us without waiting.
	clientMac := computeHMAC(token, clientNonce)
	buf := make([]byte, 64)
	copy(buf[:32], clientNonce)
	copy(buf[32:], clientMac)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("failed to write client auth: %w", err)
	}

	// 3. Read ServerNonce (32 bytes) + ServerMac (32 bytes)
	respBuf := make([]byte, 64)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return fmt.Errorf("failed to read server response: %w", err)
	}
	serverNonce := respBuf[:32]
	serverMac := respBuf[32:]

	// 4. Verify ServerMac == HMAC(Token, ServerNonce + ClientNonce)
	// The server includes our nonce in its MAC to prove it's a fresh response to our request.
	// We must create a new slice to avoid modifying serverNonce if append reallocates or overwrites.
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
	// 1. Read ClientNonce (32 bytes) + ClientMac (32 bytes)
	buf := make([]byte, 64)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("failed to read client auth: %w", err)
	}
	clientNonce := buf[:32]
	clientMac := buf[32:]

	// 2. Verify ClientMac == HMAC(Token, ClientNonce)
	expectedClientMac := computeHMAC(token, clientNonce)
	if !hmac.Equal(clientMac, expectedClientMac) {
		return errors.New("client authentication failed: invalid MAC")
	}

	// 3. Generate ServerNonce (32 bytes)
	serverNonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverNonce); err != nil {
		return fmt.Errorf("failed to generate server nonce: %w", err)
	}

	// 4. Send ServerNonce + ServerMac(Token, ServerNonce + ClientNonce)
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
