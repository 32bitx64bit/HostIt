package crypto

import (
	"crypto/rand"
	"testing"
)

func TestAgentIdentitySignVerify(t *testing.T) {
	pub, priv, err := GenerateAgentIdentity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(pub) != AgentPublicKeyLen {
		t.Fatalf("pubkey len = %d, want %d", len(pub), AgentPublicKeyLen)
	}

	challenge := make([]byte, 32)
	rand.Read(challenge)
	sig := SignIdentityChallenge(priv, challenge)

	if !VerifyIdentityChallenge(pub, challenge, sig) {
		t.Fatal("valid signature rejected")
	}

	// Wrong challenge, wrong key, and tampered signature must all fail.
	other := make([]byte, 32)
	rand.Read(other)
	if VerifyIdentityChallenge(pub, other, sig) {
		t.Error("signature accepted for a different challenge")
	}
	otherPub, _, _ := GenerateAgentIdentity()
	if VerifyIdentityChallenge(otherPub, challenge, sig) {
		t.Error("signature accepted under a different public key")
	}
	sig[0] ^= 0xff
	if VerifyIdentityChallenge(pub, challenge, sig) {
		t.Error("tampered signature accepted")
	}
}

func TestVerifyIdentityChallengeRejectsBadPubkeyLen(t *testing.T) {
	if VerifyIdentityChallenge([]byte{1, 2, 3}, []byte("x"), []byte("y")) {
		t.Error("verify accepted a malformed public key")
	}
}
