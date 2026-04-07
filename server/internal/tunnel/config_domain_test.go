package tunnel

import (
	"strings"
	"testing"
	"time"
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

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
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

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must not include ports") {
		t.Fatalf("Validate() error = %v, want invalid domain failure", err)
	}
}
