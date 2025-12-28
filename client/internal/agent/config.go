package agent

import (
	"net"
	"strconv"
	"strings"
)

// RemoteRoute is sent by the server after HELLO.
// The agent derives local targets from PublicAddr (defaults to 127.0.0.1:<port>).
type RemoteRoute struct {
	Name       string
	Proto      string // "tcp", "udp", or "both"
	PublicAddr string // server listen addr (host:port)
	// TCPNoDelay enables TCP_NODELAY (low latency) for this route.
	// If true, the agent will disable Nagle on the data TCP connection and the local backend TCP connection.
	TCPNoDelay bool
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
	// DisableUDPEncryption disables application-layer encryption for the agent<->server
	// UDP data channel (used for UDP forwarding). By default it is enabled.
	DisableUDPEncryption bool
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
