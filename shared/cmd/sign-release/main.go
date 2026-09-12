package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"hostit/shared/updater"
)

func main() {
	tag := flag.String("tag", "", "GitHub release tag to sign (e.g. v3.2.2)")
	keyPath := flag.String("key", "", "path to hex Ed25519 seed/private key (or set HOSTIT_UPDATE_SIGNING_KEY)")
	zipDir := flag.String("dir", "", "directory of zip files to sign (default: download from the GitHub release)")
	upload := flag.Bool("upload", true, "upload .sig files to the GitHub release")
	flag.Parse()

	if strings.TrimSpace(*tag) == "" && strings.TrimSpace(*zipDir) == "" {
		fatal("usage: sign-release -tag v3.2.2 [-dir ./dist] [-key /path/to/key.hex]")
	}

	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		fatal(err.Error())
	}
	if !ed25519.PublicKey(priv[32:]).Equal(updater.UpdatePublicKey) {
		fatal("signing key does not match the public key baked into the updater; running installs will reject these signatures")
	}

	dir := strings.TrimSpace(*zipDir)
	cleanup := false
	if dir == "" {
		dir, err = os.MkdirTemp("", "hostit-sign-*")
		if err != nil {
			fatal(err.Error())
		}
		cleanup = true
		if err := run("gh", "release", "download", *tag, "-p", "*.zip", "-D", dir); err != nil {
			fatal("download release zips: " + err.Error())
		}
	}
	if cleanup {
		defer os.RemoveAll(dir)
	}

	zips, err := filepath.Glob(filepath.Join(dir, "*.zip"))
	if err != nil || len(zips) == 0 {
		fatal("no zip files found to sign")
	}

	var sigs []string
	for _, zipPath := range zips {
		zipBytes, err := os.ReadFile(zipPath)
		if err != nil {
			fatal(err.Error())
		}
		sig := ed25519.Sign(priv, zipBytes)
		sigPath := zipPath + ".sig"
		if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
			fatal(err.Error())
		}
		if !ed25519.Verify(updater.UpdatePublicKey, zipBytes, sig) {
			fatal("self-check failed for " + filepath.Base(zipPath))
		}
		fmt.Println("signed", filepath.Base(zipPath))
		sigs = append(sigs, sigPath)
	}

	if !*upload || strings.TrimSpace(*tag) == "" {
		fmt.Println("wrote", len(sigs), "signature files")
		return
	}
	args := append([]string{"release", "upload", *tag, "--clobber"}, sigs...)
	if err := run("gh", args...); err != nil {
		fatal("upload signatures: " + err.Error())
	}
	fmt.Println("uploaded", len(sigs), "signatures to", *tag)
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw := strings.TrimSpace(os.Getenv("HOSTIT_UPDATE_SIGNING_KEY"))
	if strings.TrimSpace(path) == "" && raw == "" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, ".config", "hostit", "update-signing.key")
		}
	}
	if strings.TrimSpace(path) != "" {
		b, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			raw = strings.TrimSpace(string(b))
		}
	}
	if raw == "" {
		return nil, fmt.Errorf("missing signing key; set HOSTIT_UPDATE_SIGNING_KEY or pass -key")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("signing key must be hex: %w", err)
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, fmt.Errorf("signing key must be 32-byte seed or 64-byte private key, got %d bytes", len(decoded))
	}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
