package agent

import (
	"crypto/cipher"
	"fmt"
	"net"
	"strconv"
	"strings"

	"hostit/shared/emailcfg"
)

type RemoteRoute struct {
	Name       string
	Proto      string // "tcp", "udp", or "both"
	PublicAddr string // server listen addr (host:port)
	LocalAddr  string // agent-side target addr (host:port)
	Encrypted  bool
	Algorithm  string
	DerivedKey []byte      `json:"-"`
	UDPCipher  cipher.AEAD `json:"-"`
}

func (r RemoteRoute) EffectiveLocalAddr() string {
	if s := strings.TrimSpace(r.LocalAddr); s != "" {
		return s
	}
	return localTargetFromPublicAddr(r.PublicAddr)
}

type Config struct {
	Server       string
	Token        string
	DisableTLS   bool
	TLSPinSHA256 string
	Email        emailcfg.Config        `json:"-"`
	Routes       map[string]RemoteRoute `json:"-"`
}

func (c Config) Validate() error {
	var errs []string

	if strings.TrimSpace(c.Server) == "" {
		errs = append(errs, "server address is required")
	}

	if strings.TrimSpace(c.Token) == "" {
		errs = append(errs, "token is required")
	}

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
	if err != nil || pi+1 <= 0 || pi+1 > 65535 {
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
	return s, defaultPort
}

func localTargetFromPublicAddr(publicAddr string) string {
	if strings.TrimSpace(publicAddr) == "" {
		return "127.0.0.1"
	}
	if strings.HasPrefix(publicAddr, ":") {
		port := strings.TrimPrefix(publicAddr, ":")
		if port == "" {
			return "127.0.0.1"
		}
		return net.JoinHostPort("127.0.0.1", port)
	}

	_, port, err := net.SplitHostPort(publicAddr)
	if err == nil {
		return net.JoinHostPort("127.0.0.1", port)
	}

	if idx := strings.LastIndex(publicAddr, ":"); idx != -1 && idx+1 < len(publicAddr) {
		port = publicAddr[idx+1:]
		if port != "" {
			return net.JoinHostPort("127.0.0.1", port)
		}
	}
	return "127.0.0.1"
}
