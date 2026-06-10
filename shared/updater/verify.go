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
	0x50, 0xe6, 0x97, 0x59, 0x71, 0x52, 0x8b, 0x05,
	0x36, 0xd0, 0x1a, 0xbc, 0x27, 0x62, 0x63, 0x9f,
	0x96, 0x00, 0xe3, 0x4c, 0xe4, 0xdb, 0x14, 0x35,
	0xc4, 0x9e, 0x24, 0xdd, 0x7b, 0x4d, 0x0c, 0x7c,
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
