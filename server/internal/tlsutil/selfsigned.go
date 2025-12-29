package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// EnsureSelfSigned writes a self-signed ECDSA certificate/key pair if the files
// do not already exist. It always returns the SHA256 fingerprint of the cert DER.
func EnsureSelfSigned(certFile, keyFile string) (fingerprintHex string, err error) {
	if certFile == "" || keyFile == "" {
		return "", fmt.Errorf("certFile/keyFile required")
	}

	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)

	if certExists && keyExists {
		der, err := readFirstCertDER(certFile)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(der)
		return hex.EncodeToString(sum[:]), nil
	}

	return writeSelfSigned(certFile, keyFile, "hostit-tunnel")
}

// RegenerateSelfSigned always overwrites the certificate/key with a new self-signed
// ECDSA pair and returns the SHA256 fingerprint of the cert DER.
func RegenerateSelfSigned(certFile, keyFile string) (fingerprintHex string, err error) {
	if certFile == "" || keyFile == "" {
		return "", fmt.Errorf("certFile/keyFile required")
	}
	return writeSelfSigned(certFile, keyFile, "hostit-tunnel")
}

// EnsureSelfSignedDashboard writes a self-signed ECDSA certificate/key pair if the files
// do not already exist, using a dashboard-specific certificate identity.
func EnsureSelfSignedDashboard(certFile, keyFile string) (fingerprintHex string, err error) {
	if certFile == "" || keyFile == "" {
		return "", fmt.Errorf("certFile/keyFile required")
	}

	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)

	if certExists && keyExists {
		der, err := readFirstCertDER(certFile)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(der)
		return hex.EncodeToString(sum[:]), nil
	}

	return writeSelfSigned(certFile, keyFile, "hostit-dashboard")
}

// RegenerateSelfSignedDashboard always overwrites the certificate/key with a new self-signed
// ECDSA pair and returns the SHA256 fingerprint of the cert DER.
func RegenerateSelfSignedDashboard(certFile, keyFile string) (fingerprintHex string, err error) {
	if certFile == "" || keyFile == "" {
		return "", fmt.Errorf("certFile/keyFile required")
	}
	return writeSelfSigned(certFile, keyFile, "hostit-dashboard")
}

func writeSelfSigned(certFile, keyFile string, commonName string) (fingerprintHex string, err error) {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil && filepath.Dir(certFile) != "." {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o755); err != nil && filepath.Dir(keyFile) != "." {
		return "", err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"hostit"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", err
	}

	certOut, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return "", err
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return "", err
	}

	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func readFirstCertDER(certFile string) ([]byte, error) {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no CERTIFICATE PEM block", certFile)
	}
	return blk.Bytes, nil
}
