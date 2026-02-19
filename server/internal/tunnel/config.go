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
	// TCPNoDelay controls TCP_NODELAY for this route's TCP connections.
	// If nil, the default is enabled (true).
	TCPNoDelay *bool
	// TunnelTLS controls whether the agent<->server data channel should be TLS-encrypted
	// for this route.
	//
	// Note: this is only applicable if the server is configured with an insecure data
	// listener as well (DataAddrInsecure). If nil, the default is enabled (true).
	TunnelTLS *bool
	// Preconnect controls how many pre-handshaked data TCP connections the agent should
	// keep ready to reduce per-connection pairing latency.
	// If nil, the default is 4 for TCP-capable routes.
	// If 0, the agent dials on-demand.
	Preconnect *int
}

// IsEnabled returns true if the route is enabled (default is true).
func (r *RouteConfig) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
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

	// Preconnect must be non-negative
	if r.Preconnect != nil && *r.Preconnect < 0 {
		errs = append(errs, fmt.Sprintf("route %q: preconnect must be >= 0", r.Name))
	}

	if len(errs) > 0 {
		return &ConfigValidationError{Errors: errs}
	}
	return nil
}

type ServerConfig struct {
	ControlAddr string
	DataAddr    string
	// DataAddrInsecure optionally enables a second (non-TLS) TCP listener for the agent
	// data channel. This is only used when TLS is enabled globally and some routes have
	// TunnelTLS=false.
	DataAddrInsecure string
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
	// MaxPendingConns limits the total number of pending connections waiting for agent
	// attachment. This is a DoS protection measure. Default: 10000. Set to 0 to disable.
	MaxPendingConns *int `json:",omitempty"`
	// MaxPendingPerIP limits pending connections per source IP address.
	// This prevents a single client from exhausting the pending connection pool.
	// Default: 100. Set to 0 to disable.
	MaxPendingPerIP *int `json:",omitempty"`
	// DashboardInterval controls the bucket width for the time-series dashboard.
	// Smaller values give higher resolution at the cost of more memory.
	// Default: 30s. Minimum: 5s. Maximum: 10m.
	DashboardInterval time.Duration `json:",omitempty"`
	Routes            []RouteConfig

	// AgentHeartbeatInterval is the interval between heartbeat pings to the agent.
	// Default: 5s. Minimum: 1s. Maximum: 30s.
	AgentHeartbeatInterval time.Duration `json:",omitempty"`
	// AgentHeartbeatTimeout is the time after which an unresponsive agent is disconnected.
	// Default: 10s. Must be greater than AgentHeartbeatInterval.
	AgentHeartbeatTimeout time.Duration `json:",omitempty"`

	// UDP configuration options
	// UDPBufferSize sets the socket buffer size for UDP connections.
	// Default: 64MB. Increase for high-throughput scenarios.
	UDPBufferSize *int `json:",omitempty"`
	// UDPQueueSize sets the queue size for UDP packet processing.
	// Default: 262144.
	UDPQueueSize *int `json:",omitempty"`
	// UDPMaxPayload sets the maximum UDP payload size. 0 = no limit.
	UDPMaxPayload *int `json:",omitempty"`
	// UDPWorkerCount sets the number of UDP worker goroutines.
	// Default: NumCPU * 4.
	UDPWorkerCount *int `json:",omitempty"`
	// UDPReaderCount sets the number of UDP reader goroutines.
	// Default: NumCPU.
	UDPReaderCount *int `json:",omitempty"`
	// UDPEncryptionMode sets the encryption mode for UDP packets.
	// Options: "none", "aes-gcm". Default: "aes-gcm".
	UDPEncryptionMode string `json:",omitempty"`
	// DisableUDPEncryption disables UDP encryption.
	DisableUDPEncryption bool `json:",omitempty"`
	// UDPKeyID is the current UDP encryption key ID.
	UDPKeyID uint32 `json:",omitempty"`
	// UDPKeySaltB64 is the base64-encoded salt for the current UDP key.
	UDPKeySaltB64 string `json:",omitempty"`
	// UDPKeyCreatedUnix is the Unix timestamp when the current UDP key was created.
	UDPKeyCreatedUnix int64 `json:",omitempty"`
	// UDPPrevKeyID is the previous UDP encryption key ID (for key rotation).
	UDPPrevKeyID uint32 `json:",omitempty"`
	// UDPPrevKeySaltB64 is the base64-encoded salt for the previous UDP key.
	UDPPrevKeySaltB64 string `json:",omitempty"`
	// QUICEnabled enables QUIC protocol support for UDP traffic.
	QUICEnabled bool `json:",omitempty"`
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

	// MaxPendingConns validation
	if c.MaxPendingConns != nil && *c.MaxPendingConns < 0 {
		errs = append(errs, "max_pending_conns must be >= 0")
	}

	// MaxPendingPerIP validation
	if c.MaxPendingPerIP != nil && *c.MaxPendingPerIP < 0 {
		errs = append(errs, "max_pending_per_ip must be >= 0")
	}

	// DashboardInterval validation
	if c.DashboardInterval > 0 && c.DashboardInterval < 5*time.Second {
		errs = append(errs, "dashboard_interval must be at least 5s")
	}
	if c.DashboardInterval > 10*time.Minute {
		errs = append(errs, "dashboard_interval must be at most 10m")
	}

	// Agent heartbeat validation
	if c.AgentHeartbeatInterval > 0 && c.AgentHeartbeatInterval < 1*time.Second {
		errs = append(errs, "agent_heartbeat_interval must be at least 1s")
	}
	if c.AgentHeartbeatInterval > 30*time.Second {
		errs = append(errs, "agent_heartbeat_interval must be at most 30s")
	}
	if c.AgentHeartbeatTimeout > 0 && c.AgentHeartbeatTimeout < 2*time.Second {
		errs = append(errs, "agent_heartbeat_timeout must be at least 2s")
	}
	if c.AgentHeartbeatTimeout > 60*time.Second {
		errs = append(errs, "agent_heartbeat_timeout must be at most 60s")
	}
	if c.AgentHeartbeatInterval > 0 && c.AgentHeartbeatTimeout > 0 && c.AgentHeartbeatTimeout <= c.AgentHeartbeatInterval {
		errs = append(errs, "agent_heartbeat_timeout must be greater than agent_heartbeat_interval")
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
