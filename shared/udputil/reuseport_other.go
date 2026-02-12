//go:build !linux
// +build !linux

package udputil

import (
	"net"
)

// ListenUDPReusePort creates a UDP listener.
// On non-Linux systems, SO_REUSEPORT is not available, so this falls back
// to a standard UDP listener. Multiple readers are not supported on these platforms.
func ListenUDPReusePort(network, addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP(network, udpAddr)
}
