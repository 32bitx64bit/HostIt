//go:build !linux

package tunnel

import (
	"net"
	"time"
)

// setTCPUserTimeout is a no-op on non-Linux platforms.
// TCP_USER_TIMEOUT is Linux-specific; other OSes rely on keepalive
// probe retries for dead-peer detection.
func setTCPUserTimeout(_ *net.TCPConn, _ time.Duration) {}
