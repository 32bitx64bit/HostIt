//go:build linux

package agent

import (
	"net"

	"golang.org/x/sys/unix"
)

func setTCPQuickACK(conn net.Conn, on bool) {
	tc := unwrapTCPConn(conn)
	if tc == nil {
		return
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	v := 0
	if on {
		v = 1
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, v)
	})
}
