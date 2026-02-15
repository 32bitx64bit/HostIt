//go:build !linux

package connutil

import (
	"errors"
	"net"
)

// TCP Fast Open and other TCP optimizations are not available on non-Linux platforms.

// CheckTFOSupport returns false on non-Linux platforms.
func CheckTFOSupport() bool {
	return false
}

// CheckBBRSupport returns false on non-Linux platforms.
func CheckBBRSupport() bool {
	return false
}

// CheckECNSupport returns false on non-Linux platforms.
func CheckECNSupport() bool {
	return false
}

// EnableTCPFastOpen is a no-op on non-Linux platforms.
func EnableTCPFastOpen(listener *net.TCPListener) error {
	return nil
}

// EnableBBR is a no-op on non-Linux platforms.
func EnableBBR(conn *net.TCPConn) error {
	return nil
}

// EnableECN is a no-op on non-Linux platforms.
func EnableECN(conn *net.TCPConn) error {
	return nil
}

// EnableAllTCPOptimizations is a no-op on non-Linux platforms.
func EnableAllTCPOptimizations(conn *net.TCPConn) error {
	return nil
}

// TCPFastOpenConnect falls back to regular connect on non-Linux platforms.
func TCPFastOpenConnect(network, addr string, initialData []byte) (net.Conn, error) {
	return net.Dial(network, addr)
}

// TCPInfo contains TCP connection information.
type TCPInfo struct {
	RTT         uint32
	RTTVar      uint32
	SndCwnd     uint32
	SndSsthresh uint32
	RcvMss      uint32
}

// GetTCPInfo returns an error on non-Linux platforms.
func GetTCPInfo(conn *net.TCPConn) (*TCPInfo, error) {
	return nil, ErrNotSupported
}

// ErrNotSupported is returned when a feature is not supported on the current platform.
var ErrNotSupported = errors.New("feature not supported on this platform")
