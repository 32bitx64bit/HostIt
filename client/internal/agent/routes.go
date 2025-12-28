package agent

import (
	"net"
	"strings"
)

func routeHasTCP(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "tcp", "both":
		return true
	default:
		return false
	}
}

func routeHasUDP(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "udp", "both":
		return true
	default:
		return false
	}
}

func localTargetFromPublicAddr(publicAddr string) (string, bool) {
	pa := strings.TrimSpace(publicAddr)
	if pa == "" {
		return "", false
	}
	_, port, err := net.SplitHostPort(pa)
	if err != nil {
		// Handle ":1234" variants robustly.
		if strings.HasPrefix(pa, ":") {
			_, port, err = net.SplitHostPort("0.0.0.0" + pa)
		}
	}
	if err != nil || strings.TrimSpace(port) == "" {
		return "", false
	}
	return net.JoinHostPort("127.0.0.1", port), true
}
