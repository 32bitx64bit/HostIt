package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"
)

// The UDP data plane is connectionless and otherwise unauthenticated, so the
// server would adopt the source address of any datagram as "the agent" — a
// single spoofed packet could hijack or blackhole all tunneled UDP.
// Register packets therefore carry a token-keyed authenticator over a fresh
// timestamp and random nonce. The server only adopts/refreshes the agent
// address from a register whose MAC verifies and whose timestamp is recent,
// and dedupes the nonce to block replays within the freshness window.
const (
	udpRegisterLabel = "udp-register"
	udpRegisterMACLen = 16
	// UDPRegisterPayloadLen is the wire size of an authenticated register
	// payload: timestamp(8) || random(8) || truncated HMAC(16).
	UDPRegisterPayloadLen = 8 + 8 + udpRegisterMACLen
)

// UDPRegisterKey is the freshness identifier (timestamp||random) the server
// tracks to reject replayed register payloads.
type UDPRegisterKey [16]byte

// BuildUDPRegister constructs a fresh authenticated register payload bound to
// token. A new timestamp and random nonce are generated on every call, so
// callers must build a new payload per send rather than caching one. It
// returns (nil, nil) when token is empty (no shared secret to authenticate).
func BuildUDPRegister(token string) ([]byte, error) {
	if token == "" {
		return nil, nil
	}
	buf := make([]byte, UDPRegisterPayloadLen)
	binary.BigEndian.PutUint64(buf[0:8], uint64(time.Now().UnixMilli()))
	if _, err := io.ReadFull(rand.Reader, buf[8:16]); err != nil {
		return nil, err
	}
	mac := udpRegisterMAC(token, buf[0:16])
	copy(buf[16:UDPRegisterPayloadLen], mac)
	return buf, nil
}

// VerifyUDPRegister validates a register payload against token within
// [now-window, now+window]. On success it returns the freshness key (for
// replay tracking) and true. It performs the constant-time MAC comparison
// before the timestamp check so a forged payload cannot probe the window.
func VerifyUDPRegister(token string, payload []byte, now time.Time, window time.Duration) (UDPRegisterKey, bool) {
	var key UDPRegisterKey
	if token == "" || len(payload) != UDPRegisterPayloadLen {
		return key, false
	}
	expected := udpRegisterMAC(token, payload[0:16])
	if !hmac.Equal(payload[16:UDPRegisterPayloadLen], expected) {
		return key, false
	}
	ts := int64(binary.BigEndian.Uint64(payload[0:8]))
	delta := now.UnixMilli() - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > window.Milliseconds() {
		return key, false
	}
	copy(key[:], payload[0:16])
	return key, true
}

func udpRegisterMAC(token string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(udpRegisterLabel))
	mac.Write(data)
	return mac.Sum(nil)[:udpRegisterMACLen]
}
