package mail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"hostit/shared/emailcfg"
)

type mailTLSSetup struct {
	Config          *tls.Config
	Source          string
	ACMEHTTPAddr    string
	ACMEHTTPHandler http.Handler
	Warmup          func(context.Context) error
}

func ensureMailTLSConfig(dataDir string, cfg emailcfg.Config) (*mailTLSSetup, error) {
	if cfg.AutoTLS {
		host := strings.TrimSpace(cfg.EffectiveMailHost())
		fallbackCertFile := filepath.Join(dataDir, "tls", "mail-local.crt")
		fallbackKeyFile := filepath.Join(dataDir, "tls", "mail-local.key")
		if _, err := ensureMailSelfSigned(fallbackCertFile, fallbackKeyFile, host); err != nil {
			return nil, err
		}
		fallbackPair, err := tls.LoadX509KeyPair(fallbackCertFile, fallbackKeyFile)
		if err != nil {
			return nil, err
		}
		mgr := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(filepath.Join(dataDir, "tls", "acme")),
			Email:  strings.TrimSpace(cfg.ACMEEmail),
			HostPolicy: func(_ context.Context, name string) error {
				if normalizeMailHostname(name) != normalizeMailHostname(host) {
					return fmt.Errorf("mail host not configured for automatic TLS: %s", name)
				}
				return nil
			},
		}
		tlsCfg := mgr.TLSConfig()
		tlsCfg.MinVersion = tls.VersionTLS12
		getACMECert := tlsCfg.GetCertificate
		tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if shouldUseLocalMailTLSFallback(hello) {
				return &fallbackPair, nil
			}
			hello = effectiveMailClientHello(hello, host)
			if getACMECert == nil {
				return &fallbackPair, nil
			}
			cert, err := getACMECert(hello)
			if err != nil && isLoopbackMailClient(hello) {
				return &fallbackPair, nil
			}
			return cert, err
		}
		return &mailTLSSetup{
			Config:          tlsCfg,
			Source:          "lets-encrypt",
			ACMEHTTPAddr:    cfg.ACMEHTTPAddr,
			ACMEHTTPHandler: mgr.HTTPHandler(http.NotFoundHandler()),
			Warmup: func(ctx context.Context) error {
				_, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
				return err
			},
		}, nil
	}

	cfgHost := cfg.EffectiveMailHost()
	certFile := cfg.TLSCertPath
	keyFile := cfg.TLSKeyPath
	source := "custom"
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if certFile == "" && keyFile == "" {
		source = "self-signed"
		certFile = filepath.Join(dataDir, "tls", "mail.crt")
		keyFile = filepath.Join(dataDir, "tls", "mail.key")
		if _, err := ensureMailSelfSigned(certFile, keyFile, cfgHost); err != nil {
			return nil, err
		}
	} else if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("mail TLS cert and key paths must both be set")
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &mailTLSSetup{Config: &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}, Source: source}, nil
}

func normalizeMailHostname(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	return strings.TrimSuffix(host, ".")
}

func shouldUseLocalMailTLSFallback(hello *tls.ClientHelloInfo) bool {
	if hello == nil {
		return true
	}
	if !isLoopbackMailClient(hello) {
		return false
	}
	switch normalizeMailHostname(hello.ServerName) {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func effectiveMailClientHello(hello *tls.ClientHelloInfo, host string) *tls.ClientHelloInfo {
	host = normalizeMailHostname(host)
	if hello == nil {
		if host == "" {
			return nil
		}
		return &tls.ClientHelloInfo{ServerName: host}
	}
	if normalizeMailHostname(hello.ServerName) != "" || host == "" {
		return hello
	}
	clone := *hello
	clone.ServerName = host
	return &clone
}

func isLoopbackMailClient(hello *tls.ClientHelloInfo) bool {
	if hello == nil || hello.Conn == nil {
		return false
	}
	addr := hello.Conn.RemoteAddr()
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func ensureMailSelfSigned(certFile, keyFile, host string) (string, error) {
	if certFile == "" || keyFile == "" {
		return "", fmt.Errorf("certFile/keyFile required")
	}
	if fileExists(certFile) && fileExists(keyFile) {
		der, err := readFirstCertDER(certFile)
		if err != nil {
			return "", err
		}
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr == nil && time.Until(cert.NotAfter) > 30*24*time.Hour {
			sum := sha256.Sum256(der)
			return hex.EncodeToString(sum[:]), nil
		}
	}
	return writeMailSelfSigned(certFile, keyFile, host)
}

func writeMailSelfSigned(certFile, keyFile, host string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil && filepath.Dir(certFile) != "." {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o755); err != nil && filepath.Dir(keyFile) != "." {
		return "", err
	}
	if host = strings.TrimSpace(host); host == "" {
		host = "localhost"
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
			CommonName:   host,
			Organization: []string{"hostit-mail"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(730 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              uniqueSANs([]string{host, "localhost"}),
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

func uniqueSANs(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(strings.ToLower(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
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
