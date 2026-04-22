package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestTLSConfigWithPin_WithoutPinRequiresExplicitInsecure(t *testing.T) {
	t.Parallel()

	// Without pin and without InsecureTLS, should error
	_, err := tlsConfigWithPin(Config{})
	if err == nil {
		t.Fatal("tlsConfigWithPin(empty) error = nil, want error")
	}

	// Without pin but with InsecureTLS, should succeed
	cfg, err := tlsConfigWithPin(Config{InsecureTLS: true})
	if err != nil {
		t.Fatalf("tlsConfigWithPin(InsecureTLS=true) error = %v, want nil", err)
	}
	if cfg == nil {
		t.Fatal("tlsConfigWithPin(InsecureTLS=true) = nil")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("tlsConfigWithPin(InsecureTLS=true).InsecureSkipVerify = false, want true")
	}
	if cfg.VerifyPeerCertificate != nil {
		t.Fatal("tlsConfigWithPin(InsecureTLS=true).VerifyPeerCertificate != nil, want nil")
	}
}

func TestTLSConfigWithPin_WithPinVerifiesLeafHash(t *testing.T) {
	t.Parallel()

	rawCert := []byte("leaf-cert")
	sum := sha256.Sum256(rawCert)
	pin := hex.EncodeToString(sum[:])
	cfg, err := tlsConfigWithPin(Config{TLSPinSHA256: pin})
	if err != nil {
		t.Fatalf("tlsConfigWithPin(pin) error = %v, want nil", err)
	}
	if cfg == nil {
		t.Fatal("tlsConfigWithPin(pin) = nil")
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
