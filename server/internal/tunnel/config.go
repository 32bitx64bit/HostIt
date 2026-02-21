package tunnel

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
)

// Validation errors are returned as a single error with multiple messages.
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
	Name       string
	Proto      string // "tcp", "udp", or "both"
	PublicAddr string // listen address (host:port)
	// Enabled controls whether the route is active.
	// If nil, the default is enabled (true).
	// Disabled routes are not exposed and the client will not forward traffic.
	Enabled *bool
	// Encrypted controls whether the tunnel traffic for this route is encrypted.
	// If nil, the default is false.
	Encrypted *bool
}

// IsEnabled returns true if the route is enabled (default is true).
func (r RouteConfig) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// IsEncrypted returns true if the route is encrypted (default is false).
func (r RouteConfig) IsEncrypted() bool {
	if r.Encrypted == nil {
		return false
	}
	return *r.Encrypted
}

// validateRouteName validates that a route name contains only safe characters.
// Route names are used in log messages, dashboard display, and map keys,
// so we restrict them to alphanumeric characters, hyphens, and underscores.
// This prevents log injection, display issues, and potential map key collisions.
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
	// Prevent reserved names that could cause confusion
	switch strings.ToLower(name) {
	case "_system", "system", "default", "all", "any":
		return fmt.Errorf("route name %q is reserved", name)
	}
	return nil
}

// Validate validates the route configuration.
func (r *RouteConfig) Validate() error {
	var errs []string

	// Name is required and must be valid
	if strings.TrimSpace(r.Name) == "" {
		errs = append(errs, "route name is required")
	} else if err := validateRouteName(r.Name); err != nil {
		errs = append(errs, err.Error())
	}

	// Proto must be valid
	switch strings.ToLower(strings.TrimSpace(r.Proto)) {
	case "tcp", "udp", "both":
		// valid
	case "":
		errs = append(errs, fmt.Sprintf("route %q: proto is required", r.Name))
	default:
		errs = append(errs, fmt.Sprintf("route %q: invalid proto %q (must be tcp, udp, or both)", r.Name, r.Proto))
	}

	// PublicAddr is required and must be a valid address
	if strings.TrimSpace(r.PublicAddr) == "" {
		errs = append(errs, fmt.Sprintf("route %q: public_addr is required", r.Name))
	} else if _, err := net.ResolveTCPAddr("tcp", r.PublicAddr); err != nil {
		// Try UDP if TCP fails (for UDP-only routes)
		if _, err := net.ResolveUDPAddr("udp", r.PublicAddr); err != nil {
			errs = append(errs, fmt.Sprintf("route %q: invalid public_addr %q: %v", r.Name, r.PublicAddr, err))
		}
	}

	if len(errs) > 0 {
		return &ConfigValidationError{Errors: errs}
	}
	return nil
}

type ServerConfig struct {
	ControlAddr string
	DataAddr    string
	// PublicAddr is kept for backwards compatibility. If Routes is empty, a default
	// TCP route named "default" is created from PublicAddr.
	PublicAddr string
	Token      string
	// DisableTLS disables TLS on the agent<->server control/data TCP listeners.
	// By default TLS is enabled.
	DisableTLS bool
	// TLSCertFile and TLSKeyFile are PEM files used when TLS is enabled.
	TLSCertFile string
	TLSKeyFile  string
	// WebHTTPS enables HTTPS for the server dashboard listener (the -web address).
	// When enabled, the dashboard serves via TLS using WebTLSCertFile/WebTLSKeyFile.
	WebHTTPS bool
	// WebTLSCertFile and WebTLSKeyFile are PEM files used for dashboard HTTPS.
	// If empty, defaults are used alongside the main config file.
	WebTLSCertFile string
	WebTLSKeyFile  string
	PairTimeout    time.Duration
	// DashboardInterval controls the bucket width for the time-series dashboard.
	// Smaller values give higher resolution at the cost of more memory.
	// Default: 30s. Minimum: 5s. Maximum: 10m.
	DashboardInterval time.Duration `json:",omitempty"`
	// EncryptionAlgorithm specifies the global encryption standard for routes that have encryption enabled.
	// Supported values: "aes-128", "aes-256", "none". Default is "aes-128".
	EncryptionAlgorithm string `json:",omitempty"`
	Routes            []RouteConfig
}

// Validate validates the server configuration.
func (c *ServerConfig) Validate() error {
	var errs []string

	// Token is required
	if strings.TrimSpace(c.Token) == "" {
		errs = append(errs, "token is required")
	}

	// ControlAddr is required
	if strings.TrimSpace(c.ControlAddr) == "" {
		errs = append(errs, "control_addr is required")
	}

	// DataAddr is required
	if strings.TrimSpace(c.DataAddr) == "" {
		errs = append(errs, "data_addr is required")
	}

	// TLS validation
	if !c.DisableTLS {
		if strings.TrimSpace(c.TLSCertFile) == "" {
			errs = append(errs, "tls_cert_file is required when TLS is enabled")
		}
		if strings.TrimSpace(c.TLSKeyFile) == "" {
			errs = append(errs, "tls_key_file is required when TLS is enabled")
		}
	}

	// Web HTTPS validation
	if c.WebHTTPS {
		if strings.TrimSpace(c.WebTLSCertFile) == "" {
			errs = append(errs, "web_tls_cert_file is required when web_https is enabled")
		}
		if strings.TrimSpace(c.WebTLSKeyFile) == "" {
			errs = append(errs, "web_tls_key_file is required when web_https is enabled")
		}
	}

	// PairTimeout validation
	if c.PairTimeout < 0 {
		errs = append(errs, "pair_timeout must be >= 0")
	}

	// DashboardInterval validation
	if c.DashboardInterval > 0 && c.DashboardInterval < 5*time.Second {
		errs = append(errs, "dashboard_interval must be at least 5s")
	}
	if c.DashboardInterval > 10*time.Minute {
		errs = append(errs, "dashboard_interval must be at most 10m")
	}

	// Route validation
	routeNames := make(map[string]bool)
	for i := range c.Routes {
		if err := c.Routes[i].Validate(); err != nil {
			if ve, ok := err.(*ConfigValidationError); ok {
				errs = append(errs, ve.Errors...)
			} else {
				errs = append(errs, err.Error())
			}
		}
		// Check for duplicate route names
		if routeNames[c.Routes[i].Name] {
			errs = append(errs, fmt.Sprintf("duplicate route name %q", c.Routes[i].Name))
		}
		routeNames[c.Routes[i].Name] = true
	}

	if len(errs) > 0 {
		return &ConfigValidationError{Errors: errs}
	}
	return nil
}
