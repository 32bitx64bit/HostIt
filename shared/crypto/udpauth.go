package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"
)

// UDP register packets carry a token-keyed authenticator with timestamp,
// nonce, and session ID to prevent spoofing and replay attacks.
const (
	udpRegisterLabel  = "udp-register-v2"
	udpRegisterMACLen = 16
	UDPSessionIDLen = 16
	// UDPRegisterPayloadLen = timestamp(8) || random(8) || sessionID(16) || mac(16)
	UDPRegisterPayloadLen = 8 + 8 + UDPSessionIDLen + udpRegisterMACLen
)

// UDPRegisterKey is the timestamp||random freshness identifier.
type UDPRegisterKey [16]byte

type UDPSessionID [UDPSessionIDLen]byte

// NewUDPSessionID generates a fresh random session ID.
func NewUDPSessionID() (UDPSessionID, error) {
	var id UDPSessionID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, err
	}
	return id, nil
}

// BuildUDPRegister builds an authenticated register payload for token.
// Returns nil when token is empty.
func BuildUDPRegister(token string, sessionID UDPSessionID) ([]byte, error) {
	if token == "" {
		return nil, nil
	}
	buf := make([]byte, UDPRegisterPayloadLen)
	binary.BigEndian.PutUint64(buf[0:8], uint64(time.Now().UnixMilli()))
	if _, err := io.ReadFull(rand.Reader, buf[8:16]); err != nil {
		return nil, err
	}
	copy(buf[16:32], sessionID[:])
	mac := udpRegisterMAC(token, buf[0:32])
	copy(buf[32:UDPRegisterPayloadLen], mac)
	return buf, nil
}

// VerifyUDPRegister checks payload validity within the time window.
// Returns the freshness key, session ID, and ok.
func VerifyUDPRegister(token string, payload []byte, now time.Time, window time.Duration) (UDPRegisterKey, UDPSessionID, bool) {
	var key UDPRegisterKey
	var sessionID UDPSessionID
	if token == "" || len(payload) != UDPRegisterPayloadLen {
		return key, sessionID, false
	}
	expected := udpRegisterMAC(token, payload[0:32])
	if !hmac.Equal(payload[32:UDPRegisterPayloadLen], expected) {
		return key, sessionID, false
	}
	ts := int64(binary.BigEndian.Uint64(payload[0:8]))
	delta := now.UnixMilli() - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > window.Milliseconds() {
		return key, sessionID, false
	}
	copy(key[:], payload[0:16])
	copy(sessionID[:], payload[16:32])
	return key, sessionID, true
}

func udpRegisterMAC(token string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(udpRegisterLabel))
	mac.Write(data)
	return mac.Sum(nil)[:udpRegisterMACLen]
}
