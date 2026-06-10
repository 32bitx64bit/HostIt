package crypto

import (
	"testing"
	"time"
)

func TestUDPRegisterRoundTrip(t *testing.T) {
	sessionID, err := NewUDPSessionID()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildUDPRegister("token", sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != UDPRegisterPayloadLen {
		t.Fatalf("payload length = %d, want %d", len(payload), UDPRegisterPayloadLen)
	}

	now := time.Now()
	key, gotSession, ok := VerifyUDPRegister("token", payload, now, 30*time.Second)
	if !ok {
		t.Fatal("valid register rejected")
	}
	if gotSession != sessionID {
		t.Fatalf("session ID mismatch: got %x want %x", gotSession, sessionID)
	}
	var zeroKey UDPRegisterKey
	if key == zeroKey {
		t.Fatal("freshness key is zero")
	}

	if _, _, ok := VerifyUDPRegister("wrong-token", payload, now, 30*time.Second); ok {
		t.Fatal("register verified under wrong token")
	}
	if _, _, ok := VerifyUDPRegister("token", payload[:len(payload)-1], now, 30*time.Second); ok {
		t.Fatal("truncated register verified")
	}
	tampered := append([]byte(nil), payload...)
	tampered[20] ^= 1 // flip a session ID bit
	if _, _, ok := VerifyUDPRegister("token", tampered, now, 30*time.Second); ok {
		t.Fatal("tampered session ID verified")
	}
	if _, _, ok := VerifyUDPRegister("token", payload, now.Add(time.Minute), 30*time.Second); ok {
		t.Fatal("stale register verified outside window")
	}
}

func TestUDPRegisterEmptyToken(t *testing.T) {
	sessionID, _ := NewUDPSessionID()
	payload, err := BuildUDPRegister("", sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		t.Fatal("empty token must produce no register payload")
	}
	if _, _, ok := VerifyUDPRegister("", make([]byte, UDPRegisterPayloadLen), time.Now(), time.Minute); ok {
		t.Fatal("empty token must never verify")
	}
}

func TestUDPRegisterFreshPerCall(t *testing.T) {
	sessionID, _ := NewUDPSessionID()
	p1, err := BuildUDPRegister("token", sessionID)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := BuildUDPRegister("token", sessionID)
	if err != nil {
		t.Fatal(err)
	}
	k1, _, ok1 := VerifyUDPRegister("token", p1, time.Now(), time.Minute)
	k2, _, ok2 := VerifyUDPRegister("token", p2, time.Now(), time.Minute)
	if !ok1 || !ok2 {
		t.Fatal("fresh registers rejected")
	}
	if k1 == k2 {
		t.Fatal("two registers produced the same freshness key (replay dedup would collide)")
	}
}
