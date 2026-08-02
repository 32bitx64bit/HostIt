package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Current UDP register packets carry both a token-keyed authenticator and an
// agent-identity signature. The signature binds the UDP session to the unique
// server nonce from one authenticated control connection.
const (
	udpRegisterMACLen = 16
	UDPSessionIDLen   = 16
	MaxAgentIDLen     = 255

	boundUDPRegisterLabel     = "udp-register-v4"
	boundUDPIdentityLabel     = "hostit-udp-register-identity-v1"
	UDPControlNonceLen        = 32
	boundUDPRegisterMagicLen  = 4
	boundUDPRegisterPrefixLen = boundUDPRegisterMagicLen + 8 + 8 +
		UDPSessionIDLen + UDPControlNonceLen
	BoundUDPRegisterMinLen = boundUDPRegisterPrefixLen + 1 +
		ed25519.SignatureSize + udpRegisterMACLen
)

var boundUDPRegisterMagic = [boundUDPRegisterMagicLen]byte{'H', 'U', 'R', 4}

// UDPRegisterKey is the timestamp||random freshness identifier.
type UDPRegisterKey [16]byte

type UDPSessionID [UDPSessionIDLen]byte

// UDPControlNonce is the fresh server nonce from the authenticated control
// handshake. It identifies one specific control-session generation.
type UDPControlNonce [UDPControlNonceLen]byte

// BoundUDPRegister is a parsed v4 registration proof. The deployment token
// authenticates the envelope, while the identity signature binds the claimed
// agent and UDP session to one authenticated control generation. The observed
// datagram source is associated with this proof by the server; it is not a
// field the NATed client can sign in advance.
type BoundUDPRegister struct {
	Key          UDPRegisterKey
	SessionID    UDPSessionID
	ControlNonce UDPControlNonce
	AgentID      string

	signed     []byte
	signature  [ed25519.SignatureSize]byte
	validUntil time.Time
}

// NewUDPSessionID generates a fresh random session ID.
func NewUDPSessionID() (UDPSessionID, error) {
	var id UDPSessionID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, err
	}
	return id, nil
}

// NewUDPControlNonce copies a 32-byte control handshake nonce into its fixed
// representation. It rejects malformed values instead of silently truncating.
func NewUDPControlNonce(nonce []byte) (UDPControlNonce, bool) {
	var out UDPControlNonce
	if len(nonce) != len(out) {
		return out, false
	}
	copy(out[:], nonce)
	return out, true
}

// IsBoundUDPRegister reports whether payload uses the independently parseable
// identity-bound v4 format.
func IsBoundUDPRegister(payload []byte) bool {
	return len(payload) >= boundUDPRegisterMagicLen && bytes.Equal(payload[:boundUDPRegisterMagicLen], boundUDPRegisterMagic[:])
}

// BuildBoundUDPRegister builds the mandatory protocol-v3 UDP registration.
// sign must be the authenticated agent identity's domain-separated signing
// method (for example, Identity.Sign). The resulting proof binds the UDP
// session claim to controlNonce and cannot be produced by another token-holding
// agent that lacks this agent's identity key.
func BuildBoundUDPRegister(token string, sessionID UDPSessionID, controlNonce UDPControlNonce, agentID string, sign func([]byte) []byte) ([]byte, error) {
	if token == "" {
		return nil, nil
	}
	if sign == nil {
		return nil, fmt.Errorf("agent identity signer is required")
	}
	if len(agentID) > MaxAgentIDLen {
		return nil, fmt.Errorf("agent id too long: %d > %d bytes", len(agentID), MaxAgentIDLen)
	}

	signedLen := boundUDPRegisterPrefixLen + 1 + len(agentID)
	buf := make([]byte, signedLen+ed25519.SignatureSize+udpRegisterMACLen)
	copy(buf[:boundUDPRegisterMagicLen], boundUDPRegisterMagic[:])
	off := boundUDPRegisterMagicLen
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(time.Now().UnixMilli()))
	off += 8
	if _, err := io.ReadFull(rand.Reader, buf[off:off+8]); err != nil {
		return nil, err
	}
	off += 8
	copy(buf[off:off+UDPSessionIDLen], sessionID[:])
	off += UDPSessionIDLen
	copy(buf[off:off+UDPControlNonceLen], controlNonce[:])
	off += UDPControlNonceLen
	buf[off] = byte(len(agentID))
	off++
	copy(buf[off:signedLen], agentID)

	signature := sign(boundUDPIdentityMessage(buf[:signedLen]))
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid agent identity signature length: %d", len(signature))
	}
	copy(buf[signedLen:signedLen+ed25519.SignatureSize], signature)
	macStart := signedLen + ed25519.SignatureSize
	mac := boundUDPRegisterMAC(token, buf[:macStart])
	copy(buf[macStart:], mac)
	return buf, nil
}

// ParseBoundUDPRegister verifies the v4 envelope HMAC and freshness and
// returns the canonical identity-signed fields. Call VerifyIdentity before
// associating the observed datagram source. The parsed proof owns its signing data,
// so later mutation of payload cannot change the verification result.
func ParseBoundUDPRegister(token string, payload []byte, now time.Time, window time.Duration) (BoundUDPRegister, bool) {
	var reg BoundUDPRegister
	if token == "" || len(payload) < BoundUDPRegisterMinLen || !IsBoundUDPRegister(payload) {
		return reg, false
	}

	agentLenOffset := boundUDPRegisterPrefixLen
	agentIDLen := int(payload[agentLenOffset])
	signedLen := boundUDPRegisterPrefixLen + 1 + agentIDLen
	macStart := signedLen + ed25519.SignatureSize
	if len(payload) != macStart+udpRegisterMACLen {
		return reg, false
	}
	expected := boundUDPRegisterMAC(token, payload[:macStart])
	if !hmac.Equal(payload[macStart:], expected) {
		return reg, false
	}

	off := boundUDPRegisterMagicLen
	timestamp := binary.BigEndian.Uint64(payload[off : off+8])
	if !udpRegisterTimestampValid(timestamp, now, window) {
		return reg, false
	}
	reg.validUntil = time.UnixMilli(int64(timestamp)).Add(window)
	copy(reg.Key[:], payload[off:off+16])
	off += 16
	copy(reg.SessionID[:], payload[off:off+UDPSessionIDLen])
	off += UDPSessionIDLen
	copy(reg.ControlNonce[:], payload[off:off+UDPControlNonceLen])
	reg.AgentID = string(payload[agentLenOffset+1 : signedLen])
	reg.signed = append([]byte(nil), payload[:signedLen]...)
	copy(reg.signature[:], payload[signedLen:macStart])
	return reg, true
}

// ValidUntil is the final instant at which this parsed proof can pass the
// freshness check. Replay caches must retain the proof through this instant,
// including when the signer's clock is ahead of the verifier's clock.
func (r BoundUDPRegister) ValidUntil() time.Time {
	return r.validUntil
}

// VerifyIdentity verifies the session/control claim against the public key
// retained on the corresponding authenticated control session.
func (r BoundUDPRegister) VerifyIdentity(publicKey []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(r.signed) == 0 {
		return false
	}
	return VerifyIdentityChallenge(publicKey, boundUDPIdentityMessage(r.signed), r.signature[:])
}

func boundUDPRegisterMAC(token string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(boundUDPRegisterLabel))
	mac.Write(data)
	return mac.Sum(nil)[:udpRegisterMACLen]
}

func boundUDPIdentityMessage(signed []byte) []byte {
	msg := make([]byte, 0, len(boundUDPIdentityLabel)+len(signed))
	msg = append(msg, boundUDPIdentityLabel...)
	msg = append(msg, signed...)
	return msg
}

func udpRegisterTimestampValid(timestamp uint64, now time.Time, window time.Duration) bool {
	if window < 0 || timestamp > uint64(1<<63-1) {
		return false
	}
	created := time.UnixMilli(int64(timestamp))
	return !created.Before(now.Add(-window)) && !created.After(now.Add(window))
}
