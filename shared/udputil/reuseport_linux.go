//go:build linux

package udputil

import (
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortEnabled indicates whether SO_REUSEPORT is available and enabled.
var reusePortEnabled bool
var reusePortOnce sync.Once

// IsReusePortAvailable returns true if SO_REUSEPORT is available on this system.
func IsReusePortAvailable() bool {
	reusePortOnce.Do(func() {
		// Check kernel version - SO_REUSEPORT is available since Linux 3.9
		// but we want 4.5+ for proper load balancing
		reusePortEnabled = true // Assume available on modern Linux
		if env := os.Getenv("HOSTIT_DISABLE_REUSEPORT"); env != "" && env != "0" {
			reusePortEnabled = false
		}
	})
	return reusePortEnabled
}

// ListenUDPWithReusePort creates a UDP listener with SO_REUSEPORT enabled.
// This allows multiple sockets to bind to the same port, enabling true
// parallel processing at the kernel level.
func ListenUDPWithReusePort(network, addr string) (*net.UDPConn, error) {
	if !IsReusePortAvailable() {
		return net.ListenUDP(network, mustResolveUDPAddr(network, addr))
	}

	// Create socket with SO_REUSEPORT
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// Enable SO_REUSEPORT for load balancing across multiple sockets
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if opErr != nil {
					return
				}
				// Also set SO_REUSEADDR for good measure
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	conn, err := lc.ListenPacket(nil, network, addr)
	if err != nil {
		return nil, err
	}

	return conn.(*net.UDPConn), nil
}

// ListenPacketWithReusePort creates a PacketConn with SO_REUSEPORT enabled.
func ListenPacketWithReusePort(network, addr string) (net.PacketConn, error) {
	if !IsReusePortAvailable() {
		return net.ListenPacket(network, addr)
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if opErr != nil {
					return
				}
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	return lc.ListenPacket(nil, network, addr)
}

func mustResolveUDPAddr(network, addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		panic(err)
	}
	return a
}
