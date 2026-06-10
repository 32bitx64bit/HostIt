//go:build linux

package netutil

import (
	"net"
	"syscall"
	"time"
)

// tcpUserTimeout is the value of TCP_USER_TIMEOUT (see <netinet/tcp.h>).
// It bounds how long transmitted data may remain unacknowledged before
// the kernel resets the connection.
const tcpUserTimeout = 0x12

// SetTCPUserTimeout sets TCP_USER_TIMEOUT on the underlying TCP socket.
// A non-positive timeout, a non-TCP connection, or a closed socket is a
// no-op. The timeout is rounded to whole milliseconds.
func SetTCPUserTimeout(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	tcpConn := UnwrapTCPConn(conn)
	if tcpConn == nil {
		return nil
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}
	ms := int(timeout / time.Millisecond)
	if ms <= 0 {
		ms = 1
	}
	var setErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, ms)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return setErr
}
