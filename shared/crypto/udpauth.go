package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// UDP register packets carry a token-keyed authenticator (timestamp, nonce,
// session ID, agent ID) to defeat replay/spoofing and attribute UDP traffic.
const (
	udpRegisterLabel  = "udp-register-v3"
	udpRegisterMACLen = 16
	UDPSessionIDLen   = 16
	MaxAgentIDLen     = 255
	// timestamp(8) || random(8) || sessionID(16)
	udpRegisterPrefixLen = 8 + 8 + UDPSessionIDLen
	// prefix || agentIDLen(1) || mac(16), with a zero-length agent ID.
	UDPRegisterMinLen = udpRegisterPrefixLen + 1 + udpRegisterMACLen
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
func BuildUDPRegister(token string, sessionID UDPSessionID, agentID string) ([]byte, error) {
	if token == "" {
		return nil, nil
	}
	if len(agentID) > MaxAgentIDLen {
		return nil, fmt.Errorf("agent id too long: %d > %d bytes", len(agentID), MaxAgentIDLen)
	}
	macStart := udpRegisterPrefixLen + 1 + len(agentID)
	buf := make([]byte, macStart+udpRegisterMACLen)
	binary.BigEndian.PutUint64(buf[0:8], uint64(time.Now().UnixMilli()))
	if _, err := io.ReadFull(rand.Reader, buf[8:16]); err != nil {
		return nil, err
	}
	copy(buf[16:32], sessionID[:])
	buf[udpRegisterPrefixLen] = byte(len(agentID))
	copy(buf[udpRegisterPrefixLen+1:macStart], agentID)
	mac := udpRegisterMAC(token, buf[:macStart])
	copy(buf[macStart:], mac)
	return buf, nil
}

// VerifyUDPRegister checks payload validity within the time window.
// Returns the freshness key, session ID, agent ID, and ok.
func VerifyUDPRegister(token string, payload []byte, now time.Time, window time.Duration) (UDPRegisterKey, UDPSessionID, string, bool) {
	var key UDPRegisterKey
	var sessionID UDPSessionID
	if token == "" || len(payload) < UDPRegisterMinLen {
		return key, sessionID, "", false
	}
	agentIDLen := int(payload[udpRegisterPrefixLen])
	macStart := udpRegisterPrefixLen + 1 + agentIDLen
	if len(payload) != macStart+udpRegisterMACLen {
		return key, sessionID, "", false
	}
	expected := udpRegisterMAC(token, payload[:macStart])
	if !hmac.Equal(payload[macStart:macStart+udpRegisterMACLen], expected) {
		return key, sessionID, "", false
	}
	ts := int64(binary.BigEndian.Uint64(payload[0:8]))
	delta := now.UnixMilli() - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > window.Milliseconds() {
		return key, sessionID, "", false
	}
	copy(key[:], payload[0:16])
	copy(sessionID[:], payload[16:32])
	agentID := string(payload[udpRegisterPrefixLen+1 : macStart])
	return key, sessionID, agentID, true
}

func udpRegisterMAC(token string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(udpRegisterLabel))
	mac.Write(data)
	return mac.Sum(nil)[:udpRegisterMACLen]
}
