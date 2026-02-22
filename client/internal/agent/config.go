package agent

import (
	"crypto/cipher"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// RemoteRoute is sent by the server after HELLO.
// The agent derives local targets from PublicAddr (defaults to 127.0.0.1:<port>).
type RemoteRoute struct {
	Name       string
	Proto      string      // "tcp", "udp", or "both"
	PublicAddr string      // server listen addr (host:port)
	Encrypted  bool        // whether this route uses application-layer encryption
	Algorithm  string      // encryption algorithm to use
	DerivedKey []byte      `json:"-"` // cached derived key
	UDPCipher  cipher.AEAD `json:"-"` // cached UDP cipher
}

type Config struct {
	// Server is the tunnel server host/IP. You can optionally specify a port
	// (control port), e.g. "vps.example.com:7000".
	Server string
	// Token is mandatory and must match the server's token.
	Token string
	// DisableTLS disables TLS for agent<->server control/data TCP connections.
	// By default TLS is enabled.
	DisableTLS bool
	// TLSPinSHA256 optionally pins the server certificate by SHA256(der) hex.
	// This is recommended with self-signed certs to prevent MITM.
	TLSPinSHA256 string
	// Routes is populated by the server's HELLO message.
	Routes map[string]RemoteRoute `json:"-"`
}

// Validate validates the client configuration.
func (c Config) Validate() error {
	var errs []string

	// Server is required
	if strings.TrimSpace(c.Server) == "" {
		errs = append(errs, "server address is required")
	}

	// Token is required
	if strings.TrimSpace(c.Token) == "" {
		errs = append(errs, "token is required")
	}

	// TLSPinSHA256 validation (if provided, must be valid hex and correct length)
	if pin := strings.TrimSpace(c.TLSPinSHA256); pin != "" {
		if len(pin) != 64 {
			errs = append(errs, fmt.Sprintf("tls_pin_sha256 must be 64 characters (got %d)", len(pin)))
		}
		for _, r := range pin {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				errs = append(errs, "tls_pin_sha256 must be a valid hex string")
				break
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("configuration validation failed: %v", errs)
	}
	return nil
}

func (c Config) ControlAddr() string {
	host, port := splitHostPortOrDefault(c.Server, "7000")
	return net.JoinHostPort(host, port)
}

func (c Config) DataAddr() string {
	host, port := splitHostPortOrDefault(c.Server, "7000")
	pi, err := strconv.Atoi(port)
	if err != nil {
		return net.JoinHostPort(host, "7001")
	}
	return net.JoinHostPort(host, strconv.Itoa(pi+1))
}

func splitHostPortOrDefault(server string, defaultPort string) (host, port string) {
	s := strings.TrimSpace(server)
	if s == "" {
		return "127.0.0.1", defaultPort
	}
	h, p, err := net.SplitHostPort(s)
	if err == nil {
		if strings.TrimSpace(h) == "" {
			h = "127.0.0.1"
		}
		if strings.TrimSpace(p) == "" {
			p = defaultPort
		}
		return h, p
	}
	// If the user passed only a host/IP (no port).
	return s, defaultPort
}
