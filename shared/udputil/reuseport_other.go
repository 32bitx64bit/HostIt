//go:build !linux

package udputil

import (
	"net"
)

// IsReusePortAvailable returns false on non-Linux platforms.
func IsReusePortAvailable() bool {
	return false
}

// ListenUDPWithReusePort falls back to regular ListenUDP on non-Linux platforms.
func ListenUDPWithReusePort(network, addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP(network, udpAddr)
}

// ListenPacketWithReusePort falls back to regular ListenPacket on non-Linux platforms.
func ListenPacketWithReusePort(network, addr string) (net.PacketConn, error) {
	return net.ListenPacket(network, addr)
}
