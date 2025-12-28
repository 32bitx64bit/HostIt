package tunnel

import "time"

type RouteConfig struct {
	Name       string
	Proto      string // "tcp", "udp", or "both"
	PublicAddr string // listen address (host:port)
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
	Routes            []RouteConfig
}
