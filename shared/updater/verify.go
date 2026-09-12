package updater

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// UpdatePublicKey is the Ed25519 public key used to verify update zip signatures.
// Signatures are raw Ed25519 signatures (64 bytes) over the raw zip file bytes,
// published alongside each release asset as <assetURL>.sig.
// The corresponding private key must be kept offline / in CI.
var UpdatePublicKey = ed25519.PublicKey{
	0x9f, 0x3d, 0x31, 0xb4, 0x80, 0x10, 0x3a, 0xac,
	0xf1, 0x75, 0x68, 0x7e, 0x16, 0xe9, 0xba, 0xe4,
	0xcf, 0xa0, 0x9d, 0x43, 0x29, 0xcd, 0x40, 0x1c,
	0xc5, 0x2e, 0x86, 0x5d, 0x82, 0x80, 0x42, 0xd2,
}

func verifyZipSignature(ctx context.Context, zipPath string, assetURL string, logw io.Writer) error {
	zipBytes, err := os.ReadFile(zipPath)
	if err != nil {
		return fmt.Errorf("read zip for verification: %w", err)
	}

	sigURL := assetURL + ".sig"
	_, _ = fmt.Fprintf(logw, "Downloading signature: %s\n", sigURL)
	sig, err := downloadSig(ctx, sigURL)
	if err != nil {
		return fmt.Errorf("download signature: %w", err)
	}

	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(UpdatePublicKey, zipBytes, sig) {
		return errors.New("signature verification failed")
	}

	_, _ = fmt.Fprintf(logw, "Signature verified\n")
	return nil
}

func downloadSig(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hostit-updater")
	cl := &http.Client{Timeout: 30 * time.Second}
	res, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", res.StatusCode)
	}
	return io.ReadAll(res.Body)
}
