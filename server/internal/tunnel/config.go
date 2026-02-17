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
	// DisableUDPEncryption disables application-layer encryption for the agent<->server
	// UDP data channel (used for UDP forwarding). By default it is enabled.
	//
	// Deprecated: prefer UDPEncryptionMode.
	DisableUDPEncryption bool
	// UDPEncryptionMode controls application-layer encryption for the agent<->server
	// UDP data channel. Supported values: "none", "aes128", "aes256".
	// Default: "aes256".
	UDPEncryptionMode string
	// UDPKeyID is the current UDP encryption key version identifier.
	UDPKeyID uint32
	// UDPKeySaltB64 is the current key salt (base64, raw). The key is derived from
	// Token + salt.
	UDPKeySaltB64 string
	// UDPPrevKeyID/UDPPrevKeySaltB64 are kept to allow a short grace period during
	// key rotation.
	UDPPrevKeyID      uint32
	UDPPrevKeySaltB64 string
	// UDPKeyCreatedUnix is when the current UDP key was generated (unix seconds).
	UDPKeyCreatedUnix int64
	PairTimeout       time.Duration
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

	// UDP performance tuning options (optional, defaults applied if not set)
	// UDPReaderCount is the number of parallel reader goroutines per UDP socket.
	// Default: GOMAXPROCS/2, min 2, max 16.
	UDPReaderCount *int `json:",omitempty"`
	// UDPWorkerCount is the number of worker goroutines for packet processing.
	// Default: GOMAXPROCS*2, min 8, max 128.
	UDPWorkerCount *int `json:",omitempty"`
	// UDPQueueSize is the packet queue size between readers and workers.
	// Default: 16384.
	UDPQueueSize *int `json:",omitempty"`
	// UDPMaxPayload caps forwarded UDP payload size in bytes.
	// Default: 1400. Set to 0 to disable payload capping.
	UDPMaxPayload *int `json:",omitempty"`
	// UDPBufferSize is the kernel socket buffer size in bytes.
	// Default: 8MB (8388608).
	UDPBufferSize *int `json:",omitempty"`
	// UDPSessionBufferSize is the per-session buffer size for local UDP connections.
	// Default: 4MB (4194304).
	UDPSessionBufferSize *int `json:",omitempty"`
	// UDPBufferPoolSize is the size of each buffer in the pool in bytes.
	// Default: 64KB (65536).
	UDPBufferPoolSize *int `json:",omitempty"`
	// QUICEnabled enables QUIC protocol for UDP transport.
	// QUIC provides better reliability and congestion control.
	// Default is false (disabled).
	QUICEnabled bool `json:",omitempty"`

	// AgentHeartbeatInterval is the interval between heartbeat pings to the agent.
	// Default: 5s. Minimum: 1s. Maximum: 30s.
	AgentHeartbeatInterval time.Duration `json:",omitempty"`
	// AgentHeartbeatTimeout is the time after which an unresponsive agent is disconnected.
	// Default: 10s. Must be greater than AgentHeartbeatInterval.
	AgentHeartbeatTimeout time.Duration `json:",omitempty"`
	// UDPSessionIdleTimeout is the idle timeout for UDP sessions.
	// Default: 5 minutes. Minimum: 1 minute. Maximum: 30 minutes.
	UDPSessionIdleTimeout time.Duration `json:",omitempty"`
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

	// UDP encryption mode validation
	mode := strings.ToLower(strings.TrimSpace(c.UDPEncryptionMode))
	if mode != "" && mode != "none" && mode != "aes128" && mode != "aes256" {
		errs = append(errs, fmt.Sprintf("invalid udp_encryption_mode %q (must be none, aes128, or aes256)", c.UDPEncryptionMode))
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

	// UDP tuning validation
	if c.UDPReaderCount != nil && *c.UDPReaderCount < 1 {
		errs = append(errs, "udp_reader_count must be >= 1")
	}
	if c.UDPWorkerCount != nil && *c.UDPWorkerCount < 1 {
		errs = append(errs, "udp_worker_count must be >= 1")
	}
	if c.UDPQueueSize != nil && *c.UDPQueueSize < 1024 {
		errs = append(errs, "udp_queue_size must be >= 1024")
	}
	if c.UDPMaxPayload != nil {
		if *c.UDPMaxPayload < 0 {
			errs = append(errs, "udp_max_payload must be >= 0")
		}
		if *c.UDPMaxPayload > 65507 {
			errs = append(errs, "udp_max_payload must be <= 65507")
		}
	}
	if c.UDPBufferSize != nil && *c.UDPBufferSize < 65536 {
		errs = append(errs, "udp_buffer_size must be >= 65536")
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

	// UDP session idle timeout validation
	if c.UDPSessionIdleTimeout > 0 && c.UDPSessionIdleTimeout < 1*time.Minute {
		errs = append(errs, "udp_session_idle_timeout must be at least 1m")
	}
	if c.UDPSessionIdleTimeout > 30*time.Minute {
		errs = append(errs, "udp_session_idle_timeout must be at most 30m")
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
