package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ValidateAgentLocalHost checks a tunnel target host the agent will dial.
// Allowed: empty (caller defaults to 127.0.0.1), "localhost", loopback,
// unspecified (0.0.0.0 / ::), and private addresses (RFC1918 / ULA).
// Rejected: link-local (incl. cloud metadata), multicast, and public IPs.
func ValidateAgentLocalHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}

	// Bracketed IPv6 from JoinHostPort consumers.
	host = strings.Trim(host, "[]")

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("local_host must be an IP address or localhost (got %q)", host)
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("invalid local_host IP %q", host)
	}
	addr = addr.Unmap()

	switch {
	case addr.IsLoopback(), addr.IsUnspecified():
		return nil
	case addr.IsPrivate(): // RFC1918 + fc00::/7
		return nil
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(), addr.IsMulticast(), addr.IsInterfaceLocalMulticast():
		return fmt.Errorf("local_host %q is not allowed (link-local/multicast)", host)
	default:
		return fmt.Errorf("local_host %q is not allowed (use loopback or a private address)", host)
	}
}

// ValidateAgentLocalAddr checks a host:port the agent will dial.
func ValidateAgentLocalAddr(localAddr string) error {
	localAddr = strings.TrimSpace(localAddr)
	if localAddr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(localAddr)
	if err != nil {
		// Bare host without port — validate as host only.
		return ValidateAgentLocalHost(localAddr)
	}
	return ValidateAgentLocalHost(host)
}
