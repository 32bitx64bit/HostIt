package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func testBoundUDPRegister(t *testing.T, token, agentID string) ([]byte, []byte, UDPSessionID, UDPControlNonce) {
	t.Helper()
	pub, priv, err := GenerateAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := NewUDPSessionID()
	if err != nil {
		t.Fatal(err)
	}
	var controlNonce UDPControlNonce
	for i := range controlNonce {
		controlNonce[i] = byte(i + 1)
	}
	payload, err := BuildBoundUDPRegister(token, sessionID, controlNonce, agentID, func(challenge []byte) []byte {
		return SignIdentityChallenge(priv, challenge)
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload, pub, sessionID, controlNonce
}

func rewriteBoundUDPRegisterMAC(payload []byte, token string) {
	macStart := len(payload) - udpRegisterMACLen
	copy(payload[macStart:], boundUDPRegisterMAC(token, payload[:macStart]))
}

func TestBoundUDPRegisterRoundTrip(t *testing.T) {
	payload, pub, sessionID, controlNonce := testBoundUDPRegister(t, "token", "agent-a")
	if len(payload) != BoundUDPRegisterMinLen+len("agent-a") {
		t.Fatalf("payload length = %d, want %d", len(payload), BoundUDPRegisterMinLen+len("agent-a"))
	}
	if !IsBoundUDPRegister(payload) {
		t.Fatal("v4 payload was not recognized")
	}

	reg, ok := ParseBoundUDPRegister("token", payload, time.Now(), 30*time.Second)
	if !ok {
		t.Fatal("valid bound register rejected")
	}
	if reg.SessionID != sessionID {
		t.Fatalf("session ID = %x, want %x", reg.SessionID, sessionID)
	}
	if reg.ControlNonce != controlNonce {
		t.Fatalf("control nonce = %x, want %x", reg.ControlNonce, controlNonce)
	}
	if reg.AgentID != "agent-a" {
		t.Fatalf("agent ID = %q, want agent-a", reg.AgentID)
	}
	if reg.Key == (UDPRegisterKey{}) {
		t.Fatal("freshness key is zero")
	}
	if !reg.VerifyIdentity(pub) {
		t.Fatal("valid agent identity signature rejected")
	}

	otherPub, _, err := GenerateAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if reg.VerifyIdentity(otherPub) {
		t.Fatal("register verified under another agent identity")
	}
	if reg.VerifyIdentity(nil) {
		t.Fatal("register verified with an invalid public key")
	}
}

func TestBoundUDPRegisterIdentityCoversSessionClaim(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name: "timestamp",
			mutate: func(payload []byte) {
				payload[boundUDPRegisterMagicLen+7] ^= 1
			},
		},
		{
			name: "freshness nonce",
			mutate: func(payload []byte) {
				payload[boundUDPRegisterMagicLen+8] ^= 1
			},
		},
		{
			name: "udp session",
			mutate: func(payload []byte) {
				payload[boundUDPRegisterMagicLen+16] ^= 1
			},
		},
		{
			name: "control generation",
			mutate: func(payload []byte) {
				payload[boundUDPRegisterMagicLen+16+UDPSessionIDLen] ^= 1
			},
		},
		{
			name: "agent id",
			mutate: func(payload []byte) {
				payload[boundUDPRegisterPrefixLen+1] ^= 1
			},
		},
		{
			name: "identity signature",
			mutate: func(payload []byte) {
				signedLen := boundUDPRegisterPrefixLen + 1 + int(payload[boundUDPRegisterPrefixLen])
				payload[signedLen] ^= 1
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, pub, _, _ := testBoundUDPRegister(t, "token", "agent-a")
			tt.mutate(payload)
			// Model an attacker who possesses the shared deployment token: it can
			// repair the envelope MAC, but it cannot repair the identity proof.
			rewriteBoundUDPRegisterMAC(payload, "token")
			reg, ok := ParseBoundUDPRegister("token", payload, time.Now(), 30*time.Second)
			if !ok {
				if tt.name == "timestamp" {
					// A one-bit timestamp mutation can move the value outside the
					// freshness window, which is an equally valid rejection.
					return
				}
				t.Fatal("token-authenticated mutation did not parse")
			}
			if reg.VerifyIdentity(pub) {
				t.Fatal("identity proof accepted a modified session claim")
			}
		})
	}
}

func TestBoundUDPRegisterEnvelopeValidation(t *testing.T) {
	payload, pub, _, _ := testBoundUDPRegister(t, "token", "agent-a")
	now := time.Now()

	if _, ok := ParseBoundUDPRegister("wrong-token", payload, now, time.Minute); ok {
		t.Fatal("register verified under the wrong token")
	}
	if _, ok := ParseBoundUDPRegister("", payload, now, time.Minute); ok {
		t.Fatal("register verified with an empty token")
	}

	badMAC := append([]byte(nil), payload...)
	badMAC[len(badMAC)-1] ^= 1
	if _, ok := ParseBoundUDPRegister("token", badMAC, now, time.Minute); ok {
		t.Fatal("register with a modified MAC verified")
	}

	badMagic := append([]byte(nil), payload...)
	badMagic[0] ^= 1
	rewriteBoundUDPRegisterMAC(badMagic, "token")
	if IsBoundUDPRegister(badMagic) {
		t.Fatal("modified v4 marker was recognized")
	}
	if _, ok := ParseBoundUDPRegister("token", badMagic, now, time.Minute); ok {
		t.Fatal("register with a modified marker parsed")
	}

	badAgentLength := append([]byte(nil), payload...)
	badAgentLength[boundUDPRegisterPrefixLen]++
	if _, ok := ParseBoundUDPRegister("token", badAgentLength, now, time.Minute); ok {
		t.Fatal("register with an inconsistent agent length parsed")
	}

	for n := 0; n < len(payload); n++ {
		if _, ok := ParseBoundUDPRegister("token", payload[:n], now, time.Minute); ok {
			t.Fatalf("truncated register of length %d parsed", n)
		}
	}

	reg, ok := ParseBoundUDPRegister("token", payload, now, time.Minute)
	if !ok {
		t.Fatal("valid register rejected")
	}
	for i := range payload {
		payload[i] ^= 0xff
	}
	if !reg.VerifyIdentity(pub) {
		t.Fatal("parsed proof changed when the caller mutated its input buffer")
	}
}

func TestBoundUDPRegisterFreshnessWindow(t *testing.T) {
	payload, _, _, _ := testBoundUDPRegister(t, "token", "agent-a")
	now := time.Now()
	if _, ok := ParseBoundUDPRegister("token", payload, now.Add(31*time.Second), 30*time.Second); ok {
		t.Fatal("stale register accepted")
	}
	if _, ok := ParseBoundUDPRegister("token", payload, now.Add(-31*time.Second), 30*time.Second); ok {
		t.Fatal("register too far in the future accepted")
	}
	if _, ok := ParseBoundUDPRegister("token", payload, now, -time.Second); ok {
		t.Fatal("register accepted with a negative freshness window")
	}

	extreme := append([]byte(nil), payload...)
	for i := boundUDPRegisterMagicLen; i < boundUDPRegisterMagicLen+8; i++ {
		extreme[i] = 0xff
	}
	rewriteBoundUDPRegisterMAC(extreme, "token")
	if _, ok := ParseBoundUDPRegister("token", extreme, now, time.Minute); ok {
		t.Fatal("overflowing timestamp accepted")
	}
}

func TestBoundUDPRegisterValidityIncludesFutureClockSkew(t *testing.T) {
	payload, _, _, _ := testBoundUDPRegister(t, "token", "agent-a")
	created := time.UnixMilli(int64(binary.BigEndian.Uint64(payload[boundUDPRegisterMagicLen : boundUDPRegisterMagicLen+8])))
	const window = 30 * time.Second
	acceptedAt := created.Add(-29 * time.Second)
	reg, ok := ParseBoundUDPRegister("token", payload, acceptedAt, window)
	if !ok {
		t.Fatal("register within the allowed future-skew window was rejected")
	}
	want := created.Add(window)
	if !reg.ValidUntil().Equal(want) {
		t.Fatalf("valid until = %s, want signed timestamp plus window %s", reg.ValidUntil(), want)
	}
	if !reg.ValidUntil().After(acceptedAt.Add(window)) {
		t.Fatal("future-skewed proof was not retained beyond acceptance time plus one window")
	}
}

func TestBoundUDPRegisterInputValidation(t *testing.T) {
	sessionID, _ := NewUDPSessionID()
	var controlNonce UDPControlNonce
	validSigner := func(challenge []byte) []byte {
		_, priv, err := GenerateAgentIdentity()
		if err != nil {
			t.Fatal(err)
		}
		return SignIdentityChallenge(priv, challenge)
	}

	payload, err := BuildBoundUDPRegister("", sessionID, controlNonce, "agent", nil)
	if err != nil || payload != nil {
		t.Fatalf("empty token result = (%v, %v), want (nil, nil)", payload, err)
	}
	if _, err := BuildBoundUDPRegister("token", sessionID, controlNonce, "agent", nil); err == nil {
		t.Fatal("nil identity signer accepted")
	}
	if _, err := BuildBoundUDPRegister("token", sessionID, controlNonce, "agent", func([]byte) []byte { return []byte{1} }); err == nil {
		t.Fatal("wrong identity signature length accepted")
	}
	tooLong := string(bytes.Repeat([]byte{'x'}, MaxAgentIDLen+1))
	if _, err := BuildBoundUDPRegister("token", sessionID, controlNonce, tooLong, validSigner); err == nil {
		t.Fatal("oversized agent ID accepted")
	}
	maxAgent := string(bytes.Repeat([]byte{'x'}, MaxAgentIDLen))
	if _, err := BuildBoundUDPRegister("token", sessionID, controlNonce, maxAgent, validSigner); err != nil {
		t.Fatalf("maximum-size agent ID rejected: %v", err)
	}
}

func TestUDPControlNonceValidationAndCopy(t *testing.T) {
	source := bytes.Repeat([]byte{0x5a}, UDPControlNonceLen)
	nonce, ok := NewUDPControlNonce(source)
	if !ok {
		t.Fatal("valid control nonce rejected")
	}
	source[0] ^= 0xff
	if nonce[0] != 0x5a {
		t.Fatal("control nonce aliases caller storage")
	}
	for _, size := range []int{0, UDPControlNonceLen - 1, UDPControlNonceLen + 1} {
		if _, ok := NewUDPControlNonce(make([]byte, size)); ok {
			t.Fatalf("control nonce length %d accepted", size)
		}
	}
}

func TestBoundUDPRegisterFreshPerCall(t *testing.T) {
	_, priv, err := GenerateAgentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	signer := func(challenge []byte) []byte { return SignIdentityChallenge(priv, challenge) }
	sessionID, _ := NewUDPSessionID()
	var controlNonce UDPControlNonce
	p1, err := BuildBoundUDPRegister("token", sessionID, controlNonce, "agent", signer)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := BuildBoundUDPRegister("token", sessionID, controlNonce, "agent", signer)
	if err != nil {
		t.Fatal(err)
	}
	r1, ok1 := ParseBoundUDPRegister("token", p1, time.Now(), time.Minute)
	r2, ok2 := ParseBoundUDPRegister("token", p2, time.Now(), time.Minute)
	if !ok1 || !ok2 {
		t.Fatal("fresh registers rejected")
	}
	if r1.Key == r2.Key {
		t.Fatal("two bound registers produced the same freshness key")
	}
}
