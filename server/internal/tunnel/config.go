package tunnel

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"hostit/shared/emailcfg"
	"hostit/shared/protocol"
)

type ConfigValidationError struct {
	Errors []string
}

func (e *ConfigValidationError) Error() string {
	if len(e.Errors) == 1 {
		return e.Errors[0]
	}
	return fmt.Sprintf("configuration validation failed: %v", e.Errors)
}

type RouteConfig struct {
	Name          string
	Proto         string // "tcp", "udp", or "both"
	PublicAddr    string // listen address (host:port)
	LocalAddr     string // agent-side target address (host:port). Defaults to 127.0.0.1:<publicPort>.
	Enabled       *bool
	Encrypted     *bool
	Domain        string `json:",omitempty"`
	DomainEnabled *bool  `json:",omitempty"`
}

func (r RouteConfig) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

func (r RouteConfig) IsEncrypted() bool {
	if r.Encrypted == nil {
		return false
	}
	return *r.Encrypted
}

func (r RouteConfig) IsDomainEnabled() bool {
	if r.DomainEnabled == nil {
		return false
	}
	return *r.DomainEnabled
}

func normalizeHostname(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func validateHostname(host string) error {
	host = normalizeHostname(host)
	if host == "" {
		return fmt.Errorf("hostname is required")
	}
	if len(host) > 253 {
		return fmt.Errorf("hostname must be at most 253 characters (got %d)", len(host))
	}
	if strings.ContainsAny(host, ":/\\") {
		return fmt.Errorf("hostname must not include ports, paths, or slashes")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("hostname must be a fully-qualified domain name")
	}
	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("hostname contains an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("hostname label %q is too long", label)
		}
		for i, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return fmt.Errorf("hostname label %q contains invalid character %q", label, r)
			}
			if r == '-' && (i == 0 || i == len(label)-1) {
				return fmt.Errorf("hostname label %q must not start or end with a hyphen", label)
			}
		}
	}
	return nil
}

func hostnameWithinBase(host, base string) bool {
	host = normalizeHostname(host)
	base = normalizeHostname(base)
	if host == "" || base == "" {
		return false
	}
	return host == base || strings.HasSuffix(host, "."+base)
}

func validateRouteName(name string) error {
	name = strings.TrimSpace(name)
	if len(name) == 0 {
		return fmt.Errorf("route name is required")
	}
	if len(name) > 64 {
		return fmt.Errorf("route name must be at most 64 characters (got %d)", len(name))
	}
	for i, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return fmt.Errorf("route name contains invalid character %q at position %d (only letters, digits, hyphens, and underscores are allowed)", r, i)
		}
	}
	switch strings.ToLower(name) {
	case "_system", "system", "default", "all", "any", internalEmailInboundRouteName, internalEmailSubmissionRouteName, internalEmailSubmissionTLSRouteName, internalEmailIMAPRouteName, internalEmailIMAPTLSRouteName, internalEmailACMEHTTPRouteName, protocol.RouteMailOutboundTCP:
		return fmt.Errorf("route name %q is reserved", name)
	}
	return nil
}

func (r *RouteConfig) Validate() error {
	var errs []string

	if strings.TrimSpace(r.Name) == "" {
		errs = append(errs, "route name is required")
	} else if err := validateRouteName(r.Name); err != nil {
		errs = append(errs, err.Error())
	}

	switch strings.ToLower(strings.TrimSpace(r.Proto)) {
	case "tcp", "udp", "both":
	case "":
		errs = append(errs, fmt.Sprintf("route %q: proto is required", r.Name))
	default:
		errs = append(errs, fmt.Sprintf("route %q: invalid proto %q (must be tcp, udp, or both)", r.Name, r.Proto))
	}

	publicAddr := strings.TrimSpace(r.PublicAddr)
	localAddr := strings.TrimSpace(r.LocalAddr)
	domainEnabled := r.IsDomainEnabled()

	if publicAddr == "" && !domainEnabled {
		errs = append(errs, fmt.Sprintf("route %q: public_addr is required", r.Name))
	} else if publicAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", publicAddr); err != nil {
			if _, err := net.ResolveUDPAddr("udp", publicAddr); err != nil {
				errs = append(errs, fmt.Sprintf("route %q: invalid public_addr %q: %v", r.Name, publicAddr, err))
			}
		}
	}

	if localAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", localAddr); err != nil {
			if _, err := net.ResolveUDPAddr("udp", localAddr); err != nil {
				errs = append(errs, fmt.Sprintf("route %q: invalid local_addr %q: %v", r.Name, localAddr, err))
			}
		}
	} else if publicAddr == "" {
		errs = append(errs, fmt.Sprintf("route %q: local_addr is required when public_addr is empty", r.Name))
	}

	if domainEnabled {
		if strings.EqualFold(strings.TrimSpace(r.Proto), "udp") {
			errs = append(errs, fmt.Sprintf("route %q: domain routing requires tcp or both", r.Name))
		}
		if err := validateHostname(r.Domain); err != nil {
			errs = append(errs, fmt.Sprintf("route %q: invalid domain %q: %v", r.Name, r.Domain, err))
		}
	}

	if len(errs) > 0 {
		return &ConfigValidationError{Errors: errs}
	}
	return nil
}

type ServerConfig struct {
	ControlAddr          string
	DataAddr             string
	PublicAddr           string
	Token                string
	DisableTLS           bool
	TLSCertFile          string
	TLSKeyFile           string
	WebHTTPS             bool
	WebTLSCertFile       string
	WebTLSKeyFile        string
	DomainManagerEnabled bool          `json:",omitempty"`
	DomainHTTPAddr       string        `json:",omitempty"`
	DomainHTTPSAddr      string        `json:",omitempty"`
	DomainBase           string        `json:",omitempty"`
	DomainAutoTLS        bool          `json:",omitempty"`
	DomainACMEEmail      string        `json:",omitempty"`
	DomainCertDir        string        `json:",omitempty"`
	DomainRenewBefore    time.Duration `json:",omitempty"`
	PairTimeout          time.Duration
	DashboardInterval    time.Duration   `json:",omitempty"`
	EncryptionAlgorithm  string          `json:",omitempty"`
	Email                emailcfg.Config `json:"email,omitempty"`
	Routes               []RouteConfig
}

func (c *ServerConfig) Validate() error {
	var errs []string

	if strings.TrimSpace(c.Token) == "" {
		errs = append(errs, "token is required")
	}

	if strings.TrimSpace(c.ControlAddr) == "" {
		errs = append(errs, "control_addr is required")
	}

	if strings.TrimSpace(c.DataAddr) == "" {
		errs = append(errs, "data_addr is required")
	}

	if !c.DisableTLS {
		if strings.TrimSpace(c.TLSCertFile) == "" {
			errs = append(errs, "tls_cert_file is required when TLS is enabled")
		}
		if strings.TrimSpace(c.TLSKeyFile) == "" {
			errs = append(errs, "tls_key_file is required when TLS is enabled")
		}
	}

	if c.WebHTTPS {
		if strings.TrimSpace(c.WebTLSCertFile) == "" {
			errs = append(errs, "web_tls_cert_file is required when web_https is enabled")
		}
		if strings.TrimSpace(c.WebTLSKeyFile) == "" {
			errs = append(errs, "web_tls_key_file is required when web_https is enabled")
		}
	}

	if c.DomainManagerEnabled {
		if strings.TrimSpace(c.DomainHTTPSAddr) == "" {
			errs = append(errs, "domain_https_addr is required when domain manager is enabled")
		} else if _, err := net.ResolveTCPAddr("tcp", c.DomainHTTPSAddr); err != nil {
			errs = append(errs, fmt.Sprintf("domain_https_addr is invalid: %v", err))
		}
		if strings.TrimSpace(c.DomainHTTPAddr) != "" {
			if _, err := net.ResolveTCPAddr("tcp", c.DomainHTTPAddr); err != nil {
				errs = append(errs, fmt.Sprintf("domain_http_addr is invalid: %v", err))
			}
		}
		if err := validateHostname(c.DomainBase); err != nil {
			errs = append(errs, fmt.Sprintf("domain_base is invalid: %v", err))
		}
		if c.DomainAutoTLS && strings.TrimSpace(c.DomainHTTPAddr) == "" {
			errs = append(errs, "domain_http_addr is required when automatic domain TLS is enabled")
		}
		if c.DomainAutoTLS && strings.TrimSpace(c.DomainACMEEmail) == "" {
			errs = append(errs, "domain_acme_email is required when automatic domain TLS is enabled")
		}
		if c.DomainRenewBefore > 0 {
			if c.DomainRenewBefore < 24*time.Hour {
				errs = append(errs, "domain_renew_before must be at least 24h")
			}
			if c.DomainRenewBefore > 30*24*time.Hour {
				errs = append(errs, "domain_renew_before must be at most 720h")
			}
		}
	} else {
		if c.DomainAutoTLS {
			errs = append(errs, "domain_auto_tls requires domain manager to be enabled")
		}
	}

	if c.PairTimeout < 0 {
		errs = append(errs, "pair_timeout must be >= 0")
	}

	if c.DashboardInterval > 0 && c.DashboardInterval < 5*time.Second {
		errs = append(errs, "dashboard_interval must be at least 5s")
	}
	if c.DashboardInterval > 10*time.Minute {
		errs = append(errs, "dashboard_interval must be at most 10m")
	}

	if err := c.Email.Validate(); err != nil {
		errs = append(errs, err.Error())
	}
	if base := normalizeHostname(c.DomainBase); base != "" {
		if domain := normalizeHostname(c.Email.Domain); domain != "" && !hostnameWithinBase(domain, base) {
			errs = append(errs, fmt.Sprintf("email domain %q must match base domain %q", c.Email.Domain, c.DomainBase))
		}
		if host := normalizeHostname(c.Email.EffectiveMailHost()); host != "" && !hostnameWithinBase(host, base) {
			errs = append(errs, fmt.Sprintf("email mail host %q must match base domain %q", c.Email.EffectiveMailHost(), c.DomainBase))
		}
	}

	routeNames := make(map[string]bool)
	routeDomains := make(map[string]string)
	hasEncryptedRoute := false
	for i := range c.Routes {
		if err := c.Routes[i].Validate(); err != nil {
			if ve, ok := err.(*ConfigValidationError); ok {
				errs = append(errs, ve.Errors...)
			} else {
				errs = append(errs, err.Error())
			}
		}
		if routeNames[c.Routes[i].Name] {
			errs = append(errs, fmt.Sprintf("duplicate route name %q", c.Routes[i].Name))
		}
		routeNames[c.Routes[i].Name] = true
		if c.Routes[i].IsEncrypted() {
			hasEncryptedRoute = true
		}
		if c.Routes[i].IsDomainEnabled() {
			if !c.DomainManagerEnabled {
				errs = append(errs, fmt.Sprintf("route %q: domain routing requires domain manager to be enabled", c.Routes[i].Name))
				continue
			}
			host := normalizeHostname(c.Routes[i].Domain)
			if base := normalizeHostname(c.DomainBase); base != "" && !hostnameWithinBase(host, base) {
				errs = append(errs, fmt.Sprintf("route %q: domain %q must match base domain %q", c.Routes[i].Name, c.Routes[i].Domain, c.DomainBase))
			}
			if prev, ok := routeDomains[host]; ok {
				errs = append(errs, fmt.Sprintf("duplicate route domain %q used by %q and %q", host, prev, c.Routes[i].Name))
			} else {
				routeDomains[host] = c.Routes[i].Name
			}
		}
	}

	if c.DomainManagerEnabled && c.Email.Enabled && c.Email.AutoTLS {
		mailHost := normalizeHostname(c.Email.EffectiveMailHost())
		if prev, ok := routeDomains[mailHost]; ok {
			errs = append(errs, fmt.Sprintf("email mail host %q conflicts with managed route domain used by %q", c.Email.EffectiveMailHost(), prev))
		}
	}

	for _, internalRoute := range emailSynthRoutes(*c) {
		for _, rt := range c.Routes {
			if !rt.IsEnabled() {
				continue
			}
			proto := strings.ToLower(strings.TrimSpace(rt.Proto))
			if proto != "tcp" && proto != "both" {
				continue
			}
			if publicTCPAddrsConflict(rt.PublicAddr, internalRoute.PublicAddr) {
				errs = append(errs, fmt.Sprintf("synthesized email route %q uses public TCP %s, which conflicts with route %q on %s", internalRoute.Name, internalRoute.PublicAddr, rt.Name, rt.PublicAddr))
			}
		}
	}

	if hasEncryptedRoute {
		alg := strings.ToLower(strings.TrimSpace(c.EncryptionAlgorithm))
		if alg == "" {
			errs = append(errs, "encryption_algorithm is required when any route has encrypted=true")
		} else if alg != "aes-128" && alg != "aes-256" && alg != "none" {
			errs = append(errs, fmt.Sprintf("encryption_algorithm must be aes-128, aes-256, or none, got %q", c.EncryptionAlgorithm))
		}
	}

	if len(errs) > 0 {
		return &ConfigValidationError{Errors: errs}
	}
	return nil
}
