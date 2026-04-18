package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestTLSConfigWithPin_WithoutPinSkipsVerification(t *testing.T) {
	t.Parallel()

	cfg := tlsConfigWithPin("")
	if cfg == nil {
		t.Fatal("tlsConfigWithPin() = nil")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("tlsConfigWithPin(\"\").InsecureSkipVerify = false, want true")
	}
	if cfg.VerifyPeerCertificate != nil {
		t.Fatal("tlsConfigWithPin(\"\").VerifyPeerCertificate != nil, want nil")
	}
}

func TestTLSConfigWithPin_WithPinVerifiesLeafHash(t *testing.T) {
	t.Parallel()

	rawCert := []byte("leaf-cert")
	sum := sha256.Sum256(rawCert)
	pin := hex.EncodeToString(sum[:])
	cfg := tlsConfigWithPin(pin)
	if cfg == nil {
		t.Fatal("tlsConfigWithPin() = nil")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("tlsConfigWithPin(pin).InsecureSkipVerify = false, want true")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("tlsConfigWithPin(pin).VerifyPeerCertificate = nil")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{rawCert}, nil); err != nil {
		t.Fatalf("VerifyPeerCertificate(match) error = %v, want nil", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{[]byte("other-cert")}, nil); err == nil {
		t.Fatal("VerifyPeerCertificate(mismatch) error = nil, want mismatch error")
	}
}