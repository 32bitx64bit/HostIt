//go:build !linux

package agent

import (
	"net"
	"time"
)

// setTCPUserTimeout is a no-op on non-Linux platforms.
func setTCPUserTimeout(_ *net.TCPConn, _ time.Duration) {}
