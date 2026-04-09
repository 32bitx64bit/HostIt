package main

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"hostit/shared/emailcfg"
)

func TestParseServerEmailForm_PreservesExistingHashAndHashesNewPassword(t *testing.T) {
	t.Parallel()

	existingHash, err := bcrypt.GenerateFromPassword([]byte("old-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("email_enabled", "1")
	form.Set("email_domain", "example.com")
	form.Set("email_auto_tls", "1")
	form.Set("email_acme_email", "admin@example.com")
	form.Set("email_acme_http_addr", ":80")
	form.Set("email_dkim_selector", "mail")
	form.Set("email_dkim_key_path", "/var/lib/hostit/mail/dkim.pem")
	form.Set("email_submission_addr", "127.0.0.1:1587")
	form.Set("email_imap_addr", "127.0.0.1:1993")
	form.Set("email_max_message_mb", "50")
	form.Set("email_max_recipients", "250")
	form.Set("email_account_count", "2")
	form.Set("email_account_0_username", "admin")
	form.Set("email_account_0_enabled", "1")
	form.Set("email_account_1_username", "newuser")
	form.Set("email_account_1_password", "Password123")
	form.Set("email_account_1_enabled", "1")

	req := httptest.NewRequest("POST", "/email/save", nil)
	req.Form = form
	req.PostForm = form

	cfg, err := parseServerEmailForm(req, emailcfg.Config{
		Enabled: true,
		Domain:  "example.com",
		Accounts: []emailcfg.Account{{
			Username:     "admin",
			PasswordHash: string(existingHash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Accounts) != 2 {
		t.Fatalf("Accounts len = %d, want 2", len(cfg.Accounts))
	}
	if cfg.Accounts[0].PasswordHash != string(existingHash) {
		t.Fatal("existing password hash was not preserved")
	}
	if cfg.Accounts[1].PasswordHash == "" {
		t.Fatal("new password hash was not generated")
	}
	if !cfg.AutoTLS || cfg.ACMEEmail != "admin@example.com" || cfg.ACMEHTTPAddr != ":80" {
		t.Fatalf("ACME config = %+v, want automatic TLS values", cfg)
	}
	if cfg.DKIMSelector != "mail" || cfg.DKIMKeyPath != "/var/lib/hostit/mail/dkim.pem" {
		t.Fatalf("DKIM config = %q / %q, want configured values", cfg.DKIMSelector, cfg.DKIMKeyPath)
	}
	if cfg.MaxMessageBytes != 50*(1<<20) {
		t.Fatalf("MaxMessageBytes = %d, want %d", cfg.MaxMessageBytes, 50*(1<<20))
	}
	if cfg.MaxRecipients != 250 {
		t.Fatalf("MaxRecipients = %d, want 250", cfg.MaxRecipients)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cfg.Accounts[1].PasswordHash), []byte("Password123")); err != nil {
		t.Fatalf("new password hash does not verify: %v", err)
	}
}
