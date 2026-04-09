package emailcfg

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"unicode"
)

type Account struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash,omitempty"`
	PasswordSet  bool   `json:"password_set,omitempty"`
	Enabled      bool   `json:"enabled,omitempty"`
}

type Config struct {
	Enabled           bool      `json:"enabled,omitempty"`
	Domain            string    `json:"domain,omitempty"`
	MailHost          string    `json:"mail_host,omitempty"`
	AutoTLS           bool      `json:"auto_tls,omitempty"`
	ACMEEmail         string    `json:"acme_email,omitempty"`
	ACMEHTTPAddr      string    `json:"acme_http_addr,omitempty"`
	TLSCertPath       string    `json:"tls_cert_path,omitempty"`
	TLSKeyPath        string    `json:"tls_key_path,omitempty"`
	DKIMSelector      string    `json:"dkim_selector,omitempty"`
	DKIMKeyPath       string    `json:"dkim_key_path,omitempty"`
	InboundSMTPAddr   string    `json:"inbound_smtp_addr,omitempty"`
	SubmissionAddr    string    `json:"submission_addr,omitempty"`
	SubmissionTLSAddr string    `json:"submission_tls_addr,omitempty"`
	IMAPAddr          string    `json:"imap_addr,omitempty"`
	IMAPTLSAddr       string    `json:"imap_tls_addr,omitempty"`
	InboundSMTP       bool      `json:"inbound_smtp,omitempty"`
	MaxMessageBytes   int64     `json:"max_message_bytes,omitempty"`
	MaxRecipients     int       `json:"max_recipients,omitempty"`
	StorageLimitBytes int64     `json:"storage_limit_bytes,omitempty"`
	Accounts          []Account `json:"accounts,omitempty"`
}

func Normalize(cfg Config) Config {
	out := cfg
	out.Domain = normalizeHostname(cfg.Domain)
	out.MailHost = normalizeHostname(cfg.MailHost)
	out.AutoTLS = cfg.AutoTLS
	out.ACMEEmail = strings.TrimSpace(cfg.ACMEEmail)
	out.ACMEHTTPAddr = strings.TrimSpace(cfg.ACMEHTTPAddr)
	out.TLSCertPath = strings.TrimSpace(cfg.TLSCertPath)
	out.TLSKeyPath = strings.TrimSpace(cfg.TLSKeyPath)
	out.DKIMSelector = normalizeDKIMSelector(cfg.DKIMSelector)
	out.DKIMKeyPath = strings.TrimSpace(cfg.DKIMKeyPath)
	out.InboundSMTPAddr = strings.TrimSpace(cfg.InboundSMTPAddr)
	out.SubmissionAddr = strings.TrimSpace(cfg.SubmissionAddr)
	out.SubmissionTLSAddr = strings.TrimSpace(cfg.SubmissionTLSAddr)
	out.IMAPAddr = strings.TrimSpace(cfg.IMAPAddr)
	out.IMAPTLSAddr = strings.TrimSpace(cfg.IMAPTLSAddr)
	if len(cfg.Accounts) > 0 {
		out.Accounts = make([]Account, len(cfg.Accounts))
		for i, acct := range cfg.Accounts {
			out.Accounts[i] = Account{
				Username:     normalizeUsername(acct.Username),
				PasswordHash: strings.TrimSpace(acct.PasswordHash),
				PasswordSet:  acct.PasswordSet,
				Enabled:      acct.Enabled,
			}
			if out.Accounts[i].PasswordHash != "" {
				out.Accounts[i].PasswordSet = true
			}
		}
	}
	if out.SubmissionAddr == "" && out.Enabled {
		out.SubmissionAddr = "127.0.0.1:1587"
	}
	if out.SubmissionTLSAddr == "" && out.Enabled {
		out.SubmissionTLSAddr = "127.0.0.1:1465"
	}
	if out.IMAPAddr == "" && out.Enabled {
		out.IMAPAddr = "127.0.0.1:1143"
	}
	if out.IMAPTLSAddr == "" && out.Enabled {
		out.IMAPTLSAddr = "127.0.0.1:1993"
	}
	if out.InboundSMTP && out.InboundSMTPAddr == "" {
		out.InboundSMTPAddr = "127.0.0.1:1025"
	}
	if out.AutoTLS && out.ACMEHTTPAddr == "" {
		out.ACMEHTTPAddr = ":80"
	}
	if out.DKIMSelector == "" && (out.Enabled || out.Domain != "" || len(out.Accounts) > 0) {
		out.DKIMSelector = "hostit"
	}
	if out.MaxMessageBytes <= 0 {
		out.MaxMessageBytes = 25 << 20
	}
	if out.MaxRecipients <= 0 {
		out.MaxRecipients = 100
	}
	if out.StorageLimitBytes < 0 {
		out.StorageLimitBytes = 0
	}
	return out
}

func (c Config) EffectiveMailHost() string {
	if host := normalizeHostname(c.MailHost); host != "" {
		return host
	}
	if domain := normalizeHostname(c.Domain); domain != "" {
		return "mail." + domain
	}
	return ""
}

func (c Config) AddressFor(username string) string {
	user := normalizeUsername(username)
	domain := normalizeHostname(c.Domain)
	if user == "" || domain == "" {
		return ""
	}
	return user + "@" + domain
}

func (c Config) Validate() error {
	raw := c
	c = Normalize(c)

	active := raw.Enabled || strings.TrimSpace(raw.Domain) != "" || strings.TrimSpace(raw.MailHost) != "" || raw.AutoTLS || strings.TrimSpace(raw.ACMEEmail) != "" || strings.TrimSpace(raw.ACMEHTTPAddr) != "" || strings.TrimSpace(raw.TLSCertPath) != "" || strings.TrimSpace(raw.TLSKeyPath) != "" || strings.TrimSpace(raw.DKIMSelector) != "" || strings.TrimSpace(raw.DKIMKeyPath) != "" || strings.TrimSpace(raw.InboundSMTPAddr) != "" || strings.TrimSpace(raw.SubmissionAddr) != "" || strings.TrimSpace(raw.SubmissionTLSAddr) != "" || strings.TrimSpace(raw.IMAPAddr) != "" || strings.TrimSpace(raw.IMAPTLSAddr) != "" || raw.InboundSMTP || raw.StorageLimitBytes != 0 || len(raw.Accounts) > 0
	if !active {
		return nil
	}

	var errs []string
	if err := validateHostname(c.Domain); err != nil {
		errs = append(errs, fmt.Sprintf("email domain is invalid: %v", err))
	}
	if host := c.EffectiveMailHost(); host != "" {
		if err := validateHostname(host); err != nil {
			errs = append(errs, fmt.Sprintf("email mail_host is invalid: %v", err))
		}
	}
	if c.AutoTLS {
		if strings.TrimSpace(c.ACMEEmail) == "" {
			errs = append(errs, "email acme_email is required when automatic public TLS is enabled")
		}
		if c.ACMEHTTPAddr == "" {
			errs = append(errs, "email acme_http_addr is required when automatic public TLS is enabled")
		} else if _, err := net.ResolveTCPAddr("tcp", c.ACMEHTTPAddr); err != nil {
			errs = append(errs, fmt.Sprintf("email acme_http_addr is invalid: %v", err))
		}
		if c.TLSCertPath != "" || c.TLSKeyPath != "" {
			errs = append(errs, "email automatic public TLS cannot be combined with manual tls_cert_path/tls_key_path")
		}
	}
	if (c.TLSCertPath == "") != (c.TLSKeyPath == "") {
		errs = append(errs, "email tls_cert_path and tls_key_path must both be set together")
	}
	if c.DKIMSelector != "" {
		if err := validateDKIMSelector(c.DKIMSelector); err != nil {
			errs = append(errs, fmt.Sprintf("email dkim_selector is invalid: %v", err))
		}
	}
	if c.SubmissionAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.SubmissionAddr); err != nil {
			errs = append(errs, fmt.Sprintf("email submission_addr is invalid: %v", err))
		}
	}
	if c.SubmissionTLSAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.SubmissionTLSAddr); err != nil {
			errs = append(errs, fmt.Sprintf("email submission_tls_addr is invalid: %v", err))
		}
	}
	if c.InboundSMTP {
		if c.InboundSMTPAddr == "" {
			errs = append(errs, "email inbound_smtp_addr is required when inbound SMTP is enabled")
		} else if _, err := net.ResolveTCPAddr("tcp", c.InboundSMTPAddr); err != nil {
			errs = append(errs, fmt.Sprintf("email inbound_smtp_addr is invalid: %v", err))
		}
	}
	if c.IMAPAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.IMAPAddr); err != nil {
			errs = append(errs, fmt.Sprintf("email imap_addr is invalid: %v", err))
		}
	}
	if c.IMAPTLSAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", c.IMAPTLSAddr); err != nil {
			errs = append(errs, fmt.Sprintf("email imap_tls_addr is invalid: %v", err))
		}
	}
	if c.MaxMessageBytes < 1024 {
		errs = append(errs, "email max_message_bytes must be at least 1024")
	}
	if c.MaxMessageBytes > 100*(1<<20) {
		errs = append(errs, "email max_message_bytes must be at most 104857600")
	}
	if c.MaxRecipients < 1 {
		errs = append(errs, "email max_recipients must be at least 1")
	}
	if c.MaxRecipients > 1000 {
		errs = append(errs, "email max_recipients must be at most 1000")
	}
	if raw.StorageLimitBytes < 0 {
		errs = append(errs, "email storage_limit_bytes must be >= 0")
	}
	if c.StorageLimitBytes > 0 && c.StorageLimitBytes < 1024 {
		errs = append(errs, "email storage_limit_bytes must be at least 1024 when set")
	}

	seen := make(map[string]bool, len(c.Accounts))
	for _, acct := range c.Accounts {
		if err := validateUsername(acct.Username); err != nil {
			errs = append(errs, fmt.Sprintf("email account %q is invalid: %v", acct.Username, err))
			continue
		}
		user := normalizeUsername(acct.Username)
		if seen[user] {
			errs = append(errs, fmt.Sprintf("duplicate email account username %q", user))
			continue
		}
		if acct.Enabled && strings.TrimSpace(acct.PasswordHash) == "" {
			errs = append(errs, fmt.Sprintf("email account %q is missing a password hash", user))
		}
		seen[user] = true
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
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
		return fmt.Errorf("hostname must be at most 253 characters")
	}
	if strings.ContainsAny(host, ":/\\") {
		return fmt.Errorf("hostname must not include ports, paths, or slashes")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("hostname must be fully-qualified")
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

func normalizeUsername(username string) string {
	return strings.TrimSpace(strings.ToLower(username))
}

func normalizeDKIMSelector(selector string) string {
	return strings.TrimSpace(strings.ToLower(selector))
}

func validateDKIMSelector(selector string) error {
	selector = normalizeDKIMSelector(selector)
	if selector == "" {
		return fmt.Errorf("selector is required")
	}
	if len(selector) > 63 {
		return fmt.Errorf("selector must be at most 63 characters")
	}
	for i, r := range selector {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("selector contains invalid character %q at position %d", r, i)
	}
	return nil
}

func validateUsername(username string) error {
	username = normalizeUsername(username)
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if strings.Contains(username, "@") {
		return fmt.Errorf("username must not include @domain")
	}
	if len(username) > 64 {
		return fmt.Errorf("username must be at most 64 characters")
	}
	for i, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == '+' {
			continue
		}
		return fmt.Errorf("username contains invalid character %q at position %d", r, i)
	}
	return nil
}

func ParseByteSize(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("size is required")
	}
	i := 0
	for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("size must start with a whole number")
	}
	value, err := strconv.ParseInt(raw[:i], 10, 64)
	if err != nil {
		return 0, err
	}
	if value <= 0 {
		return 0, fmt.Errorf("size must be greater than zero")
	}
	unit := strings.ToUpper(strings.TrimSpace(raw[i:]))
	multiplier := int64(1)
	switch unit {
	case "", "B":
		multiplier = 1
	case "K", "KB", "KIB":
		multiplier = 1 << 10
	case "M", "MB", "MIB":
		multiplier = 1 << 20
	case "G", "GB", "GIB":
		multiplier = 1 << 30
	case "T", "TB", "TIB":
		multiplier = 1 << 40
	default:
		return 0, fmt.Errorf("unsupported size unit %q (use B, KB, MB, GB, or TB)", strings.TrimSpace(raw[i:]))
	}
	if value > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("size is too large")
	}
	return value * multiplier, nil
}

func FormatByteSize(n int64) string {
	if n <= 0 {
		return ""
	}
	units := []struct {
		suffix string
		value  int64
	}{
		{suffix: "TB", value: 1 << 40},
		{suffix: "GB", value: 1 << 30},
		{suffix: "MB", value: 1 << 20},
		{suffix: "KB", value: 1 << 10},
	}
	for _, unit := range units {
		if n >= unit.value && n%unit.value == 0 {
			return fmt.Sprintf("%d%s", n/unit.value, unit.suffix)
		}
	}
	return fmt.Sprintf("%dB", n)
}

func HumanByteSize(n int64) string {
	if n <= 0 {
		return "0B"
	}
	units := []struct {
		suffix string
		value  int64
	}{
		{suffix: "TB", value: 1 << 40},
		{suffix: "GB", value: 1 << 30},
		{suffix: "MB", value: 1 << 20},
		{suffix: "KB", value: 1 << 10},
	}
	for _, unit := range units {
		if n >= unit.value {
			whole := n / unit.value
			remainder := n % unit.value
			if remainder == 0 {
				return fmt.Sprintf("%d%s", whole, unit.suffix)
			}
			tenths := (remainder * 10) / unit.value
			if tenths == 0 {
				return fmt.Sprintf("%d%s", whole, unit.suffix)
			}
			return fmt.Sprintf("%d.%d%s", whole, tenths, unit.suffix)
		}
	}
	return fmt.Sprintf("%dB", n)
}
