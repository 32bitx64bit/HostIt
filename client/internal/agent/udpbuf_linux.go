//go:build linux

package agent

import (
	"net"

	"golang.org/x/sys/unix"
)

// trySetUDPBuffers attempts to set large socket buffers on a UDP connection.
// On Linux, SO_RCVBUF/SO_SNDBUF are capped by net.core.rmem_max/wmem_max
// (default ~208KB), silently ignoring requests for larger buffers. We first
// try SO_RCVBUFFORCE/SO_SNDBUFFORCE which bypass the cap (needs CAP_NET_ADMIN),
// then fall back to the regular setsockopt, then verify the actual size.
func trySetUDPBuffers(conn *net.UDPConn, size int) (actualRead, actualWrite int) {
	raw, err := conn.SyscallConn()
	if err != nil {
		_ = conn.SetReadBuffer(size)
		_ = conn.SetWriteBuffer(size)
		return 0, 0
	}

	var rOK, wOK bool
	_ = raw.Control(func(fd uintptr) {
		if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size) == nil {
			rOK = true
		}
		if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size) == nil {
			wOK = true
		}
	})

	if !rOK {
		_ = conn.SetReadBuffer(size)
	}
	if !wOK {
		_ = conn.SetWriteBuffer(size)
	}

	_ = raw.Control(func(fd uintptr) {
		v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err == nil {
			actualRead = v
		}
		v, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
		if err == nil {
			actualWrite = v
		}
	})
	return actualRead, actualWrite
}
