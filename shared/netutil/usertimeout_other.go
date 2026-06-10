//go:build !linux

package netutil

import (
	"net"
	"time"
)

// SetTCPUserTimeout is a no-op on platforms without TCP_USER_TIMEOUT.
// Dead-peer detection falls back to SetTCPKeepAliveConfig.
func SetTCPUserTimeout(conn net.Conn, timeout time.Duration) error {
	_ = conn
	_ = timeout
	return nil
}
