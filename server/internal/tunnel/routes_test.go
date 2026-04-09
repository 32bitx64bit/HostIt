package tunnel

import (
	"strings"
	"testing"

	"hostit/shared/emailcfg"
)

func TestNormalizeRoutes_GeneratesUniqueNamesForBlank(t *testing.T) {
	cfg := ServerConfig{Routes: []RouteConfig{
		{Name: "", Proto: "tcp", PublicAddr: ":10000"},
		{Name: " ", Proto: "tcp", PublicAddr: ":10001"},
		{Name: "", Proto: "udp", PublicAddr: ":10002"},
	}}

	normalizeRoutes(&cfg)

	if cfg.Routes[0].Name != "default" {
		t.Fatalf("route0 name=%q, want %q", cfg.Routes[0].Name, "default")
	}
	if cfg.Routes[1].Name != "default-2" {
		t.Fatalf("route1 name=%q, want %q", cfg.Routes[1].Name, "default-2")
	}
	if cfg.Routes[2].Name != "default-3" {
		t.Fatalf("route2 name=%q, want %q", cfg.Routes[2].Name, "default-3")
	}
}

func TestNormalizeRoutes_DedupesExplicitDuplicateNames(t *testing.T) {
	cfg := ServerConfig{Routes: []RouteConfig{
		{Name: "app", Proto: "tcp", PublicAddr: ":10000"},
		{Name: "app", Proto: "tcp", PublicAddr: ":10001"},
		{Name: "app-2", Proto: "tcp", PublicAddr: ":10002"},
		{Name: "app", Proto: "udp", PublicAddr: ":10003"},
	}}

	normalizeRoutes(&cfg)

	got := []string{cfg.Routes[0].Name, cfg.Routes[1].Name, cfg.Routes[2].Name, cfg.Routes[3].Name}
	want := []string{"app", "app-3", "app-2", "app-4"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("route%d name=%q, want %q (all=%v)", i, got[i], want[i], got)
		}
	}
}

func TestServerConfigValidate_RejectsInboundSMTPPort25Conflict(t *testing.T) {
	t.Parallel()

	cfg := ServerConfig{
		ControlAddr: ":7000",
		DataAddr:    ":7001",
		Token:       "testtoken",
		DisableTLS:  true,
		Email: emailcfg.Config{
			Enabled:         true,
			Domain:          "example.com",
			MailHost:        "mail.example.com",
			InboundSMTP:     true,
			InboundSMTPAddr: "0.0.0.0:25",
		},
		Routes: []RouteConfig{{Name: "app", Proto: "tcp", PublicAddr: ":25"}},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want conflict on public TCP 25")
	}
	if got := err.Error(); got == "" || !containsAll(got, "conflicts", "route \"app\"") {
		t.Fatalf("Validate() error = %q, want inbound SMTP conflict", got)
	}
}

func TestServerConfigValidate_RejectsSubmissionPort587Conflict(t *testing.T) {
	t.Parallel()

	cfg := ServerConfig{
		ControlAddr: ":7000",
		DataAddr:    ":7001",
		Token:       "testtoken",
		DisableTLS:  true,
		Email: emailcfg.Config{
			Enabled:           true,
			Domain:            "example.com",
			MailHost:          "mail.example.com",
			SubmissionAddr:    "127.0.0.1:1587",
			SubmissionTLSAddr: "127.0.0.1:1465",
			IMAPAddr:          "127.0.0.1:1143",
			IMAPTLSAddr:       "127.0.0.1:1993",
		},
		Routes: []RouteConfig{{Name: "app", Proto: "tcp", PublicAddr: ":587"}},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want conflict on public TCP 587")
	}
	if got := err.Error(); got == "" || !containsAll(got, "hostit_mail_submission", "route \"app\"") {
		t.Fatalf("Validate() error = %q, want synthesized submission conflict", got)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
