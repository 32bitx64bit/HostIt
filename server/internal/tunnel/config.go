package tunnel

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
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
	Name       string
	Proto      string // "tcp", "udp", or "both"
	PublicAddr string // listen address (host:port)
	LocalAddr  string // agent-side target address (host:port). Defaults to 127.0.0.1:<publicPort>.
	Enabled    *bool
	Encrypted  *bool
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
	case "_system", "system", "default", "all", "any":
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

	if strings.TrimSpace(r.PublicAddr) == "" {
		errs = append(errs, fmt.Sprintf("route %q: public_addr is required", r.Name))
	} else if _, err := net.ResolveTCPAddr("tcp", r.PublicAddr); err != nil {
		if _, err := net.ResolveUDPAddr("udp", r.PublicAddr); err != nil {
			errs = append(errs, fmt.Sprintf("route %q: invalid public_addr %q: %v", r.Name, r.PublicAddr, err))
		}
	}

	if strings.TrimSpace(r.LocalAddr) != "" {
		if _, err := net.ResolveTCPAddr("tcp", r.LocalAddr); err != nil {
			if _, err := net.ResolveUDPAddr("udp", r.LocalAddr); err != nil {
				errs = append(errs, fmt.Sprintf("route %q: invalid local_addr %q: %v", r.Name, r.LocalAddr, err))
			}
		}
	}

	if len(errs) > 0 {
		return &ConfigValidationError{Errors: errs}
	}
	return nil
}

type ServerConfig struct {
	ControlAddr         string
	DataAddr            string
	PublicAddr          string
	Token               string
	DisableTLS          bool
	TLSCertFile         string
	TLSKeyFile          string
	WebHTTPS            bool
	WebTLSCertFile      string
	WebTLSKeyFile       string
	PairTimeout         time.Duration
	DashboardInterval   time.Duration `json:",omitempty"`
	EncryptionAlgorithm string        `json:",omitempty"`
	Routes              []RouteConfig
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

	if c.PairTimeout < 0 {
		errs = append(errs, "pair_timeout must be >= 0")
	}

	if c.DashboardInterval > 0 && c.DashboardInterval < 5*time.Second {
		errs = append(errs, "dashboard_interval must be at least 5s")
	}
	if c.DashboardInterval > 10*time.Minute {
		errs = append(errs, "dashboard_interval must be at most 10m")
	}

	routeNames := make(map[string]bool)
	tcpPorts := make(map[string]string)
	udpPorts := make(map[string]string)
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

		proto := strings.ToLower(strings.TrimSpace(c.Routes[i].Proto))
		publicAddr := strings.TrimSpace(c.Routes[i].PublicAddr)
		if publicAddr != "" {
			port := extractPort(publicAddr)
			if port != "" {
				if proto == "tcp" || proto == "both" {
					if existingRoute, exists := tcpPorts[port]; exists {
						errs = append(errs, fmt.Sprintf("duplicate TCP port %q used by routes %q and %q", port, existingRoute, c.Routes[i].Name))
					} else {
						tcpPorts[port] = c.Routes[i].Name
					}
				}
				if proto == "udp" || proto == "both" {
					if existingRoute, exists := udpPorts[port]; exists {
						errs = append(errs, fmt.Sprintf("duplicate UDP port %q used by routes %q and %q", port, existingRoute, c.Routes[i].Name))
					} else {
						udpPorts[port] = c.Routes[i].Name
					}
				}
			}
		}
	}

	hasEncryptedRoute := false
	for _, rt := range c.Routes {
		if rt.IsEncrypted() {
			hasEncryptedRoute = true
			break
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

func extractPort(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.Contains(addr, ":") {
			parts := strings.Split(addr, ":")
			if len(parts) >= 2 {
				return parts[len(parts)-1]
			}
		}
		return ""
	}
	return port
}
