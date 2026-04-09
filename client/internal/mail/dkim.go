package mail

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"

	"hostit/shared/emailcfg"
)

func ensureDKIMSigner(dataDir string, cfg emailcfg.Config) (crypto.Signer, string, string, string, error) {
	selector := strings.TrimSpace(cfg.DKIMSelector)
	if selector == "" {
		selector = "hostit"
	}
	keyPath := strings.TrimSpace(cfg.DKIMKeyPath)
	source := "custom"
	if keyPath == "" {
		source = "self-generated"
		keyPath = filepath.Join(dataDir, "dkim", selector+".pem")
	}
	signer, err := loadOrCreateDKIMKey(keyPath)
	if err != nil {
		return nil, "", "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, "", "", "", err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)
	dnsName := selector + "._domainkey." + cfg.Domain
	txtValue := "v=DKIM1; k=rsa; p=" + pubB64
	return signer, dnsName, txtValue, source, nil
}

func loadOrCreateDKIMKey(path string) (crypto.Signer, error) {
	if fileExists(path) {
		return loadDKIMKey(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}); err != nil {
		return nil, err
	}
	return key, nil
}

func loadDKIMKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no private key PEM block", path)
	}
	switch blk.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s: unsupported private key type", path)
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("%s: unsupported PEM block %q", path, blk.Type)
	}
}

func signOutboundMessage(raw []byte, cfg emailcfg.Config, signer crypto.Signer, authAddress string) ([]byte, error) {
	if signer == nil {
		return raw, nil
	}
	if err := validateHeaderFrom(raw, authAddress); err != nil {
		return nil, err
	}
	var signed bytes.Buffer
	if err := dkim.Sign(&signed, bytes.NewReader(raw), &dkim.SignOptions{
		Domain:                 cfg.Domain,
		Selector:               cfg.DKIMSelector,
		Identifier:             strings.TrimSpace(strings.ToLower(authAddress)),
		Signer:                 signer,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             []string{"From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "Content-Transfer-Encoding", "Cc", "Reply-To", "Sender", "In-Reply-To", "References"},
		Expiration:             time.Now().Add(7 * 24 * time.Hour),
	}); err != nil {
		return nil, err
	}
	return signed.Bytes(), nil
}

func validateHeaderFrom(raw []byte, authAddress string) error {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("invalid message headers: %w", err)
	}
	fromHeader := strings.TrimSpace(msg.Header.Get("From"))
	if fromHeader == "" {
		return fmt.Errorf("missing From header")
	}
	list, err := mail.ParseAddressList(fromHeader)
	if err != nil {
		return fmt.Errorf("invalid From header: %w", err)
	}
	if len(list) != 1 {
		return fmt.Errorf("From header must contain exactly one address")
	}
	if authAddress != "" && !strings.EqualFold(strings.TrimSpace(list[0].Address), strings.TrimSpace(authAddress)) {
		return fmt.Errorf("From header must match authenticated mailbox")
	}
	return nil
}