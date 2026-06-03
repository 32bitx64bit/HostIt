//go:build !linux

package netutil

import (
	"net"
	"time"
)

// SetTCPUserTimeout is a no-op on platforms without TCP_USER_TIMEOUT. Dead-peer
// detection on those platforms relies on the keepalive configuration applied by
// SetTCPKeepAliveConfig.
func SetTCPUserTimeout(conn net.Conn, timeout time.Duration) error {
	_ = conn
	_ = timeout
	return nil
}
