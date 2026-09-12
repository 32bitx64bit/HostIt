package tunnel

import (
	"strings"
	"testing"
	"time"

	"hostit/shared/emailcfg"
)

func TestServerConfigValidate_AllowsManagedDomainRoute(t *testing.T) {
	domainEnabled := true
	cfg := ServerConfig{
		ControlAddr:          ":7000",
		DataAddr:             ":7001",
		Token:                "test-token",
		DisableTLS:           true,
		DomainManagerEnabled: true,
		DomainHTTPAddr:       ":80",
		DomainHTTPSAddr:      ":443",
		DomainBase:           "example.com",
		DomainAutoTLS:        true,
		DomainACMEEmail:      "admin@example.com",
		DomainRenewBefore:    7 * 24 * time.Hour,
		Routes: []RouteConfig{{
			Name:          "web",
			Proto:         "tcp",
			LocalAddr:     "127.0.0.1:3234",
			Domain:        "app.example.com",
			DomainEnabled: &domainEnabled,
		}},
	}

	cfg.Email = emailcfg.Normalize(cfg.Email)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestServerConfigValidate_RequiresDomainBaseWhenManagerEnabled(t *testing.T) {
	cfg := ServerConfig{
		ControlAddr:          ":7000",
		DataAddr:             ":7001",
		Token:                "test-token",
		DisableTLS:           true,
		DomainManagerEnabled: true,
		DomainHTTPSAddr:      ":443",
	}
	cfg.Email = emailcfg.Normalize(cfg.Email)
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "domain_base is required") {
		t.Fatalf("Validate() error = %v, want domain_base required", err)
	}
}

func TestServerConfigValidate_RejectsRouteDomainOutsideBase(t *testing.T) {
	domainEnabled := true
	cfg := ServerConfig{
		ControlAddr:          ":7000",
		DataAddr:             ":7001",
		Token:                "test-token",
		DisableTLS:           true,
		DomainManagerEnabled: true,
		DomainHTTPSAddr:      ":443",
		DomainBase:           "example.com",
		Routes: []RouteConfig{{
			Name:          "web",
			Proto:         "tcp",
			LocalAddr:     "127.0.0.1:3234",
			Domain:        "app.other.net",
			DomainEnabled: &domainEnabled,
		}},
	}

	cfg.Email = emailcfg.Normalize(cfg.Email)
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must match base domain") {
		t.Fatalf("Validate() error = %v, want base-domain validation failure", err)
	}
}

func TestServerConfigValidate_RejectsDuplicateRouteDomains(t *testing.T) {
	domainEnabled := true
	cfg := ServerConfig{
		ControlAddr:          ":7000",
		DataAddr:             ":7001",
		Token:                "test-token",
		DisableTLS:           true,
		DomainManagerEnabled: true,
		DomainHTTPSAddr:      ":443",
		DomainBase:           "example.com",
		Routes: []RouteConfig{
			{Name: "web-a", Proto: "tcp", LocalAddr: "127.0.0.1:3000", Domain: "app.example.com", DomainEnabled: &domainEnabled},
			{Name: "web-b", Proto: "tcp", LocalAddr: "127.0.0.1:3001", Domain: "app.example.com", DomainEnabled: &domainEnabled},
		},
	}

	cfg.Email = emailcfg.Normalize(cfg.Email)
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate route domain") {
		t.Fatalf("Validate() error = %v, want duplicate domain failure", err)
	}
}

func TestServerConfigValidate_RejectsDomainWithPort(t *testing.T) {
	domainEnabled := true
	cfg := ServerConfig{
		ControlAddr:          ":7000",
		DataAddr:             ":7001",
		Token:                "test-token",
		DisableTLS:           true,
		DomainManagerEnabled: true,
		DomainHTTPSAddr:      ":443",
		DomainBase:           "example.com",
		Routes: []RouteConfig{{
			Name:          "web",
			Proto:         "tcp",
			LocalAddr:     "127.0.0.1:3234",
			Domain:        "app.example.com:443",
			DomainEnabled: &domainEnabled,
		}},
	}

	cfg.Email = emailcfg.Normalize(cfg.Email)
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must not include ports") {
		t.Fatalf("Validate() error = %v, want invalid domain failure", err)
	}
}

func TestServerConfigValidate_RejectsMailHostConflictWithManagedRoute(t *testing.T) {
	domainEnabled := true
	cfg := ServerConfig{
		ControlAddr:          ":7000",
		DataAddr:             ":7001",
		Token:                "test-token",
		DisableTLS:           true,
		DomainManagerEnabled: true,
		DomainHTTPAddr:       ":80",
		DomainHTTPSAddr:      ":443",
		DomainBase:           "example.com",
		Email: emailcfg.Config{
			Enabled:   true,
			Domain:    "example.com",
			MailHost:  "app.example.com",
			AutoTLS:   true,
			ACMEEmail: "admin@example.com",
		},
		Routes: []RouteConfig{{
			Name:          "web",
			Proto:         "tcp",
			LocalAddr:     "127.0.0.1:3234",
			Domain:        "app.example.com",
			DomainEnabled: &domainEnabled,
		}},
	}

	cfg.Email = emailcfg.Normalize(cfg.Email)
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "email mail host") || !strings.Contains(err.Error(), "conflicts with managed route domain") {
		t.Fatalf("Validate() error = %v, want mail-host conflict failure", err)
	}
}

func domainManagerCfg(base string) ServerConfig {
	on := true
	cfg := ServerConfig{
		ControlAddr:          ":7000",
		DataAddr:             ":7001",
		Token:                "test-token",
		DisableTLS:           true,
		DomainManagerEnabled: true,
		DomainHTTPAddr:       ":80",
		DomainHTTPSAddr:      ":443",
		DomainBase:           base,
		DomainAutoTLS:        true,
		DomainACMEEmail:      "admin@" + base,
		Routes: []RouteConfig{{
			Name:          "route-7",
			Proto:         "tcp",
			LocalAddr:     "127.0.0.1:3234",
			Domain:        base,
			DomainEnabled: &on,
		}},
	}
	cfg.Email.Domain = base
	cfg.Email.MailHost = "email." + base
	cfg.Email = emailcfg.Normalize(cfg.Email)
	return cfg
}

func TestRewriteHostnamesForBaseChange_RemapsEmailAndRoutes(t *testing.T) {
	cfg := domainManagerCfg("vertoxo.net")
	RewriteHostnamesForBaseChange(&cfg, "vertoxo.net", "tipsyhq.org")

	if cfg.DomainBase != "tipsyhq.org" {
		t.Fatalf("DomainBase = %q, want tipsyhq.org", cfg.DomainBase)
	}
	if cfg.Email.Domain != "tipsyhq.org" {
		t.Fatalf("Email.Domain = %q, want tipsyhq.org", cfg.Email.Domain)
	}
	if cfg.Email.MailHost != "email.tipsyhq.org" {
		t.Fatalf("Email.MailHost = %q, want email.tipsyhq.org", cfg.Email.MailHost)
	}
	if cfg.Routes[0].Domain != "tipsyhq.org" {
		t.Fatalf("route domain = %q, want tipsyhq.org", cfg.Routes[0].Domain)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() after base rewrite: %v", err)
	}
}

func TestRewriteHostnamesForBaseChange_LeavesUnrelatedHosts(t *testing.T) {
	cfg := domainManagerCfg("vertoxo.net")
	cfg.Routes[0].Domain = "cdn.other.net"
	RewriteHostnamesForBaseChange(&cfg, "vertoxo.net", "tipsyhq.org")
	if cfg.Routes[0].Domain != "cdn.other.net" {
		t.Fatalf("unrelated route domain rewritten to %q", cfg.Routes[0].Domain)
	}
}

func TestRewriteHostnamesForBaseChange_InfersOldBaseFromEmail(t *testing.T) {
	cfg := domainManagerCfg("vertoxo.net")
	cfg.DomainBase = "tipsyhq.org"
	RewriteHostnamesForBaseChange(&cfg, "", "tipsyhq.org")
	if cfg.Email.Domain != "tipsyhq.org" || cfg.Email.MailHost != "email.tipsyhq.org" {
		t.Fatalf("email not remapped from empty old base: domain=%q mail=%q", cfg.Email.Domain, cfg.Email.MailHost)
	}
	if cfg.Routes[0].Domain != "tipsyhq.org" {
		t.Fatalf("route domain = %q, want tipsyhq.org", cfg.Routes[0].Domain)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() after inferred rewrite: %v", err)
	}
}

func TestAlignEmailWithDomainBase_RemapsManagedBase(t *testing.T) {
	cfg := domainManagerCfg("vertoxo.net")
	cfg.Email.Domain = "tipsyhq.org"
	cfg.Email.MailHost = "email.vertoxo.net"
	cfg.Email = emailcfg.Normalize(cfg.Email)

	AlignEmailWithDomainBase(&cfg, "vertoxo.net")

	if cfg.DomainBase != "tipsyhq.org" {
		t.Fatalf("DomainBase = %q, want tipsyhq.org", cfg.DomainBase)
	}
	if cfg.Email.MailHost != "email.tipsyhq.org" {
		t.Fatalf("Email.MailHost = %q, want email.tipsyhq.org", cfg.Email.MailHost)
	}
	if cfg.Routes[0].Domain != "tipsyhq.org" {
		t.Fatalf("route domain = %q, want tipsyhq.org", cfg.Routes[0].Domain)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() after email align: %v", err)
	}
}

func TestAlignEmailWithDomainBase_KeepsSubdomainOnSameApex(t *testing.T) {
	cfg := domainManagerCfg("vertoxo.net")
	cfg.Email.Domain = "mail.vertoxo.net"
	cfg.Email = emailcfg.Normalize(cfg.Email)

	AlignEmailWithDomainBase(&cfg, "vertoxo.net")

	if cfg.DomainBase != "vertoxo.net" {
		t.Fatalf("DomainBase changed to %q, want vertoxo.net", cfg.DomainBase)
	}
	if cfg.Email.Domain != "mail.vertoxo.net" {
		t.Fatalf("Email.Domain = %q, want mail.vertoxo.net", cfg.Email.Domain)
	}
}
