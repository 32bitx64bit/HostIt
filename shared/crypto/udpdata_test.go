package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testSessionCrypto(t *testing.T) (*UDPSessionCrypto, *UDPSessionCrypto, []byte) {
	t.Helper()
	baseKey := make([]byte, 32)
	if _, err := rand.Read(baseKey); err != nil {
		t.Fatal(err)
	}
	sessionID, err := NewUDPSessionID()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := NewUDPSessionCrypto(baseKey, sessionID[:], UDPDirClientToServer, UDPDirServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewUDPSessionCrypto(baseKey, sessionID[:], UDPDirServerToClient, UDPDirClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	return agent, server, baseKey
}

func TestUDPSessionRoundTrip(t *testing.T) {
	agent, server, _ := testSessionCrypto(t)
	aad := AppendUDPDataAAD(nil, "game", "203.0.113.9:1234")

	for _, plaintext := range [][]byte{[]byte("hello"), nil, bytes.Repeat([]byte("x"), 1400)} {
		ct, err := agent.Enc.Seal(nil, plaintext, aad)
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", len(plaintext), err)
		}
		pt, err := server.Dec.Open(nil, ct, aad)
		if err != nil {
			t.Fatalf("Open(%d bytes): %v", len(plaintext), err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("round-trip mismatch: got %q want %q", pt, plaintext)
		}
	}

	// Reverse direction uses the other key pair.
	ct, err := server.Enc.Seal(nil, []byte("reply"), aad)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := agent.Dec.Open(nil, ct, aad)
	if err != nil {
		t.Fatalf("reverse Open: %v", err)
	}
	if string(pt) != "reply" {
		t.Fatalf("reverse round-trip mismatch: %q", pt)
	}
}

// TestUDPDirectionalKeysDiffer: a packet sealed for one direction must not
// open with the other direction's key (no reflection).
func TestUDPDirectionalKeysDiffer(t *testing.T) {
	agent, _, _ := testSessionCrypto(t)
	aad := AppendUDPDataAAD(nil, "game", "client")
	ct, err := agent.Enc.Seal(nil, []byte("data"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Dec.Open(nil, ct, aad); err == nil {
		t.Fatal("c2s ciphertext opened with s2c key; directional keys must differ")
	}
}

// TestUDPSessionKeysDiffer: rotating the session ID must rotate the keys.
func TestUDPSessionKeysDiffer(t *testing.T) {
	baseKey := make([]byte, 32)
	rand.Read(baseKey)
	id1, _ := NewUDPSessionID()
	id2, _ := NewUDPSessionID()
	k1, err := DeriveUDPSessionKey(baseKey, id1[:], UDPDirClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveUDPSessionKey(baseKey, id2[:], UDPDirClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("different session IDs derived the same key")
	}
}

// TestUDPCrossRouteReplayRejected guards the AAD binding: a ciphertext
// captured on route A must not decrypt when replayed onto route B or onto a
// different client flow.
func TestUDPCrossRouteReplayRejected(t *testing.T) {
	agent, server, _ := testSessionCrypto(t)
	aadA := AppendUDPDataAAD(nil, "route-a", "1.2.3.4:1111")
	aadB := AppendUDPDataAAD(nil, "route-b", "1.2.3.4:1111")
	aadC := AppendUDPDataAAD(nil, "route-a", "5.6.7.8:2222")

	ct, err := agent.Enc.Seal(nil, []byte("payload"), aadA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Dec.Open(nil, ct, aadB); err == nil {
		t.Fatal("ciphertext replayed across routes was accepted")
	}
	if _, err := server.Dec.Open(nil, ct, aadC); err == nil {
		t.Fatal("ciphertext replayed across client flows was accepted")
	}
	// Original context still opens (failed attempts must not poison state).
	if _, err := server.Dec.Open(nil, ct, aadA); err != nil {
		t.Fatalf("legitimate packet rejected after cross-context attempts: %v", err)
	}
}

func TestUDPReplayRejected(t *testing.T) {
	agent, server, _ := testSessionCrypto(t)
	aad := AppendUDPDataAAD(nil, "game", "client")

	ct, err := agent.Enc.Seal(nil, []byte("once"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Dec.Open(nil, ct, aad); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := server.Dec.Open(nil, append([]byte(nil), ct...), aad); err != ErrUDPReplay {
		t.Fatalf("replay error = %v, want ErrUDPReplay", err)
	}
}

// TestUDPReplayWindowToleratesReorder: out-of-order delivery within the
// window must be accepted exactly once.
func TestUDPReplayWindowToleratesReorder(t *testing.T) {
	agent, server, _ := testSessionCrypto(t)
	aad := AppendUDPDataAAD(nil, "game", "client")

	var packets [][]byte
	for i := 0; i < 10; i++ {
		ct, err := agent.Enc.Seal(nil, []byte{byte(i)}, aad)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, ct)
	}
	order := []int{3, 0, 7, 1, 9, 2, 5, 4, 8, 6}
	for _, i := range order {
		if _, err := server.Dec.Open(nil, packets[i], aad); err != nil {
			t.Fatalf("reordered packet %d rejected: %v", i, err)
		}
	}
	for _, i := range order {
		if _, err := server.Dec.Open(nil, append([]byte(nil), packets[i]...), aad); err != ErrUDPReplay {
			t.Fatalf("second delivery of packet %d: error = %v, want ErrUDPReplay", i, err)
		}
	}
}

// TestUDPReplayWindowDropsTooOld: packets older than the window are dropped
// even if never seen.
func TestUDPReplayWindowDropsTooOld(t *testing.T) {
	agent, server, _ := testSessionCrypto(t)
	aad := AppendUDPDataAAD(nil, "game", "client")

	old, err := agent.Enc.Seal(nil, []byte("old"), aad)
	if err != nil {
		t.Fatal(err)
	}
	// Advance the counter far past the window.
	for i := 0; i < replayWindowBits+8; i++ {
		ct, err := agent.Enc.Seal(nil, []byte("fill"), aad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.Dec.Open(nil, ct, aad); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.Dec.Open(nil, old, aad); err != ErrUDPReplay {
		t.Fatalf("ancient packet error = %v, want ErrUDPReplay", err)
	}
}

// TestUDPEncryptorRestartAccepted: a new encryptor instance (fresh prefix,
// counter reset) over the same key must be accepted by the same decryptor —
// this models a server restart within one agent session.
func TestUDPEncryptorRestartAccepted(t *testing.T) {
	baseKey := make([]byte, 32)
	rand.Read(baseKey)
	sessionID, _ := NewUDPSessionID()
	key, err := DeriveUDPSessionKey(baseKey, sessionID[:], UDPDirServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewUDPDecryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	aad := AppendUDPDataAAD(nil, "game", "client")

	for instance := 0; instance < 3; instance++ {
		enc, err := NewUDPEncryptor(key)
		if err != nil {
			t.Fatal(err)
		}
		ct, err := enc.Seal(nil, []byte("after-restart"), aad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dec.Open(nil, ct, aad); err != nil {
			t.Fatalf("instance %d packet rejected: %v", instance, err)
		}
	}
}

func TestReplayWindowUnit(t *testing.T) {
	var w replayState
	if w.accept(0) {
		t.Fatal("counter 0 accepted; counters must start at 1")
	}
	if !w.accept(1) || w.accept(1) {
		t.Fatal("counter 1 accept/replay behavior wrong")
	}
	if !w.accept(100) || w.accept(100) {
		t.Fatal("counter 100 accept/replay behavior wrong")
	}
	if !w.accept(50) || w.accept(50) {
		t.Fatal("in-window late counter behavior wrong")
	}
	// Jump beyond the window: everything old becomes invalid.
	far := uint64(100 + replayWindowBits + 1)
	if !w.accept(far) {
		t.Fatal("far-future counter rejected")
	}
	if w.accept(100) {
		t.Fatal("counter older than window accepted")
	}
	// Word-aligned shifts.
	var w2 replayState
	for _, c := range []uint64{1, 64, 65, 128, 129, 1024} {
		if !w2.accept(c) {
			t.Fatalf("counter %d rejected", c)
		}
		if w2.accept(c) {
			t.Fatalf("counter %d replay accepted", c)
		}
	}
}

func TestUDPOpenRejectsShortAndTampered(t *testing.T) {
	agent, server, _ := testSessionCrypto(t)
	aad := AppendUDPDataAAD(nil, "game", "client")

	if _, err := server.Dec.Open(nil, []byte("short"), aad); err == nil {
		t.Fatal("short packet accepted")
	}
	ct, err := agent.Enc.Seal(nil, []byte("tamper"), aad)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 1
	if _, err := server.Dec.Open(nil, ct, aad); err == nil {
		t.Fatal("tampered packet accepted")
	}
}
