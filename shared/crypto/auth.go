package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"

	"hostit/shared/netutil"
)

// AuthenticateClient runs the 3-message challenge-response handshake
// and returns the nonces for deriving a per-session key.
func AuthenticateClient(conn net.Conn, token string) (clientNonce, serverNonce []byte, err error) {
	serverNonce = make([]byte, 32)
	if _, err = io.ReadFull(conn, serverNonce); err != nil {
		return nil, nil, fmt.Errorf("failed to read server nonce: %w", err)
	}

	clientNonce = make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, clientNonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate client nonce: %w", err)
	}

	clientMac := computeClientHMAC(token, serverNonce, clientNonce)
	buf := make([]byte, 64)
	copy(buf[:32], clientNonce)
	copy(buf[32:], clientMac)
	if _, err = netutil.WriteAll(conn, buf); err != nil {
		return nil, nil, fmt.Errorf("failed to write client auth: %w", err)
	}

	serverMac := make([]byte, 32)
	if _, err = io.ReadFull(conn, serverMac); err != nil {
		return nil, nil, fmt.Errorf("failed to read server auth: %w", err)
	}

	expectedServerMac := computeServerHMAC(token, clientNonce, serverNonce)
	if !hmac.Equal(serverMac, expectedServerMac) {
		return nil, nil, errors.New("server authentication failed: invalid MAC")
	}

	return clientNonce, serverNonce, nil
}

// AuthenticateServer runs the server side of the challenge-response handshake.
func AuthenticateServer(conn net.Conn, token string) (clientNonce, serverNonce []byte, err error) {
	serverNonce = make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, serverNonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate server nonce: %w", err)
	}

	if _, err = netutil.WriteAll(conn, serverNonce); err != nil {
		return nil, nil, fmt.Errorf("failed to write server nonce: %w", err)
	}

	buf := make([]byte, 64)
	if _, err = io.ReadFull(conn, buf); err != nil {
		return nil, nil, fmt.Errorf("failed to read client auth: %w", err)
	}
	clientNonce = buf[:32]
	clientMac := buf[32:]

	expectedClientMac := computeClientHMAC(token, serverNonce, clientNonce)
	if !hmac.Equal(clientMac, expectedClientMac) {
		return nil, nil, errors.New("client authentication failed: invalid MAC")
	}

	serverMac := computeServerHMAC(token, clientNonce, serverNonce)
	if _, err = netutil.WriteAll(conn, serverMac); err != nil {
		return nil, nil, fmt.Errorf("failed to write server auth: %w", err)
	}

	return clientNonce, serverNonce, nil
}

func computeClientHMAC(token string, serverNonce, clientNonce []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("client-auth"))
	mac.Write(serverNonce)
	mac.Write(clientNonce)
	return mac.Sum(nil)
}

func computeServerHMAC(token string, clientNonce, serverNonce []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("server-auth"))
	mac.Write(clientNonce)
	mac.Write(serverNonce)
	return mac.Sum(nil)
}
