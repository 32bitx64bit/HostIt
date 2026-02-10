//go:build linux

package tunnel

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// setTCPUserTimeout sets TCP_USER_TIMEOUT on the connection. This tells the
// kernel to abort the connection if transmitted data remains unacknowledged for
// this duration. Combined with keepalive probes, this is the fastest way to
// detect a dead peer — far faster than waiting for the default 9×75s retry
// cycle.
func setTCPUserTimeout(tc *net.TCPConn, d time.Duration) {
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	ms := int(d.Milliseconds())
	if ms <= 0 {
		ms = 15000
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, ms)
	})
}
