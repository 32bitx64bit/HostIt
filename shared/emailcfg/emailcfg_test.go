package emailcfg

import "testing"

func TestNormalize_DefaultsMailHostAndUsernames(t *testing.T) {
	cfg := Normalize(Config{
		Enabled:  true,
		Domain:   " Example.COM ",
		MailHost: "",
		Accounts: []Account{{Username: " Admin "}},
	})

	if cfg.Domain != "example.com" {
		t.Fatalf("Domain = %q, want example.com", cfg.Domain)
	}
	if cfg.EffectiveMailHost() != "mail.example.com" {
		t.Fatalf("EffectiveMailHost() = %q, want mail.example.com", cfg.EffectiveMailHost())
	}
	if cfg.Accounts[0].Username != "admin" {
		t.Fatalf("Username = %q, want admin", cfg.Accounts[0].Username)
	}
	if cfg.MaxMessageBytes != 25<<20 {
		t.Fatalf("MaxMessageBytes = %d, want %d", cfg.MaxMessageBytes, 25<<20)
	}
	if cfg.MaxRecipients != 100 {
		t.Fatalf("MaxRecipients = %d, want 100", cfg.MaxRecipients)
	}
	if cfg.DKIMSelector != "hostit" {
		t.Fatalf("DKIMSelector = %q, want hostit", cfg.DKIMSelector)
	}
}

func TestNormalize_DefaultsMailAutoTLSHTTPAddr(t *testing.T) {
	cfg := Normalize(Config{Enabled: true, Domain: "example.com", AutoTLS: true, ACMEEmail: "admin@example.com"})
	if cfg.ACMEHTTPAddr != ":80" {
		t.Fatalf("ACMEHTTPAddr = %q, want :80", cfg.ACMEHTTPAddr)
	}
}

func TestConfigValidateRejectsDuplicateAccounts(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Domain:  "example.com",
		Accounts: []Account{
			{Username: "admin"},
			{Username: "Admin"},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want duplicate account error")
	}
}

func TestConfigValidateRejectsMismatchedTLSPaths(t *testing.T) {
	cfg := Config{
		Enabled:     true,
		Domain:      "example.com",
		TLSCertPath: "/tmp/mail.crt",
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want TLS path validation error")
	}
}

func TestConfigValidateRequiresACMEEmailForAutoTLS(t *testing.T) {
	cfg := Config{Enabled: true, Domain: "example.com", AutoTLS: true}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want ACME validation error")
	}
}