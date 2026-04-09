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
	if cfg.SubmissionAddr != "127.0.0.1:1587" {
		t.Fatalf("SubmissionAddr = %q, want 127.0.0.1:1587", cfg.SubmissionAddr)
	}
	if cfg.SubmissionTLSAddr != "127.0.0.1:1465" {
		t.Fatalf("SubmissionTLSAddr = %q, want 127.0.0.1:1465", cfg.SubmissionTLSAddr)
	}
	if cfg.IMAPAddr != "127.0.0.1:1143" {
		t.Fatalf("IMAPAddr = %q, want 127.0.0.1:1143", cfg.IMAPAddr)
	}
	if cfg.IMAPTLSAddr != "127.0.0.1:1993" {
		t.Fatalf("IMAPTLSAddr = %q, want 127.0.0.1:1993", cfg.IMAPTLSAddr)
	}
	if cfg.MaxRecipients != 100 {
		t.Fatalf("MaxRecipients = %d, want 100", cfg.MaxRecipients)
	}
	if cfg.StorageLimitBytes != 0 {
		t.Fatalf("StorageLimitBytes = %d, want 0 for unlimited", cfg.StorageLimitBytes)
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

func TestParseByteSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want int64
	}{
		{raw: "5MB", want: 5 << 20},
		{raw: "1Gb", want: 1 << 30},
		{raw: "512 KB", want: 512 << 10},
		{raw: "4096", want: 4096},
	}
	for _, tt := range tests {
		got, err := ParseByteSize(tt.raw)
		if err != nil {
			t.Fatalf("ParseByteSize(%q) error = %v", tt.raw, err)
		}
		if got != tt.want {
			t.Fatalf("ParseByteSize(%q) = %d, want %d", tt.raw, got, tt.want)
		}
	}

	if _, err := ParseByteSize("abc"); err == nil {
		t.Fatal("ParseByteSize(abc) error = nil, want invalid format error")
	}
}

func TestFormatByteSize(t *testing.T) {
	t.Parallel()

	if got := FormatByteSize(1 << 30); got != "1GB" {
		t.Fatalf("FormatByteSize(1<<30) = %q, want 1GB", got)
	}
	if got := HumanByteSize((3 << 20) + (512 << 10)); got != "3.5MB" {
		t.Fatalf("HumanByteSize(3.5MB) = %q, want 3.5MB", got)
	}
}

func TestConfigValidateRejectsTooSmallStorageLimit(t *testing.T) {
	t.Parallel()

	cfg := Config{Enabled: true, Domain: "example.com", StorageLimitBytes: 512}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want storage limit validation error")
	}
}
