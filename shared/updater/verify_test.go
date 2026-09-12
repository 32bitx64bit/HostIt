package updater

import (
	"crypto/ed25519"
	"testing"
)

func TestUpdatePublicKeyLength(t *testing.T) {
	if len(UpdatePublicKey) != ed25519.PublicKeySize {
		t.Fatalf("UpdatePublicKey length = %d, want %d", len(UpdatePublicKey), ed25519.PublicKeySize)
	}
}
