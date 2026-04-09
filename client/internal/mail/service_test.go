package mail

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"golang.org/x/crypto/bcrypt"

	"hostit/shared/emailcfg"
)

func TestServiceApplyConfigAuthenticateAndDeliverLocal(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := emailcfg.Config{
		Enabled:        true,
		Domain:         "example.com",
		SubmissionAddr: "127.0.0.1:0",
		IMAPAddr:       "127.0.0.1:0",
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := svc.Status()
	if !st.TLSReady {
		t.Fatal("Status().TLSReady = false, want true")
	}
	if st.TLSCertSource != "self-signed" {
		t.Fatalf("Status().TLSCertSource = %q, want self-signed", st.TLSCertSource)
	}
	if !st.DKIMReady {
		t.Fatal("Status().DKIMReady = false, want true")
	}
	if st.DKIMDNSName != "hostit._domainkey.example.com" {
		t.Fatalf("Status().DKIMDNSName = %q, want hostit._domainkey.example.com", st.DKIMDNSName)
	}
	if st.DKIMTXTValue == "" {
		t.Fatal("Status().DKIMTXTValue = empty, want TXT record value")
	}
	if st.MaxMessageBytes != 25<<20 {
		t.Fatalf("Status().MaxMessageBytes = %d, want %d", st.MaxMessageBytes, 25<<20)
	}
	if st.MaxRecipients != 100 {
		t.Fatalf("Status().MaxRecipients = %d, want 100", st.MaxRecipients)
	}
	if _, err := os.Stat(filepath.Join(svc.dataDir, "tls", "mail.crt")); err != nil {
		t.Fatalf("expected generated mail cert: %v", err)
	}
	if _, err := os.Stat(filepath.Join(svc.dataDir, "dkim", "hostit.pem")); err != nil {
		t.Fatalf("expected generated DKIM key: %v", err)
	}

	rec, err := svc.authenticate("test@example.com", "Password123")
	if err != nil {
		t.Fatalf("authenticate() error = %v", err)
	}
	if rec.Address != "test@example.com" {
		t.Fatalf("authenticate() address = %q, want test@example.com", rec.Address)
	}

	raw := []byte("From: sender@example.net\r\nTo: test@example.com\r\nSubject: hello\r\n\r\nworld\r\n")
	if err := svc.deliverLocal("test@example.com", "INBOX", raw); err != nil {
		t.Fatal(err)
	}

	msgs, err := svc.listMessages("test")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("listMessages() len = %d, want 1", len(msgs))
	}
	if msgs[0].Mailbox != "INBOX" {
		t.Fatalf("message mailbox = %q, want INBOX", msgs[0].Mailbox)
	}

	user, err := svc.buildIMAPUser(rec, "Password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := user.Login("test@example.com", "Password123"); err != nil {
		t.Fatalf("imap login failed: %v", err)
	}
	status, err := user.Status("INBOX", &imap.StatusOptions{NumMessages: true})
	if err != nil {
		t.Fatal(err)
	}
	if status.NumMessages == nil || *status.NumMessages != 1 {
		t.Fatalf("INBOX message count = %v, want 1", status.NumMessages)
	}
}

func TestServiceAutoTLSSetsLetsEncryptSource(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := emailcfg.Config{
		Enabled:        true,
		Domain:         "example.com",
		MailHost:       "mail.example.com",
		AutoTLS:        true,
		ACMEEmail:      "admin@example.com",
		ACMEHTTPAddr:   "127.0.0.1:0",
		SubmissionAddr: "127.0.0.1:0",
		IMAPAddr:       "127.0.0.1:0",
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := svc.Status()
	if st.TLSCertSource != "lets-encrypt" {
		t.Fatalf("Status().TLSCertSource = %q, want lets-encrypt", st.TLSCertSource)
	}
	if svc.acmeHTTPLn == nil {
		t.Fatal("expected ACME HTTP listener to be running")
	}
}
