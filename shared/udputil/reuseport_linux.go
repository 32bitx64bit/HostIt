//go:build linux
// +build linux

package udputil

import (
	"net"
	"os"
	"syscall"
)

// ListenUDPReusePort creates a UDP listener with SO_REUSEPORT enabled.
// This allows multiple goroutines to bind to the same port, distributing
// incoming packets across them for better parallelism on multi-core systems.
func ListenUDPReusePort(network, addr string) (*net.UDPConn, error) {
	// Parse the address
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}

	// Create socket with SO_REUSEPORT
	sockFamily := syscall.AF_INET
	if len(udpAddr.IP) > 4 {
		sockFamily = syscall.AF_INET6
	}

	// Create socket
	fd, err := syscall.Socket(sockFamily, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}

	// Set SO_REUSEPORT
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unixSO_REUSEPORT, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Set SO_REUSEADDR as well for good measure
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Bind
	var sa syscall.Sockaddr
	if sockFamily == syscall.AF_INET6 {
		var addrBytes [16]byte
		copy(addrBytes[:], udpAddr.IP.To16())
		sa = &syscall.SockaddrInet6{
			Port: udpAddr.Port,
			Addr: addrBytes,
		}
	} else {
		var addrBytes [4]byte
		copy(addrBytes[:], udpAddr.IP.To4())
		sa = &syscall.SockaddrInet4{
			Port: udpAddr.Port,
			Addr: addrBytes,
		}
	}

	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Convert to net.UDPConn
	file := os.NewFile(uintptr(fd), "udp-socket")
	defer file.Close()

	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, net.UnknownNetworkError(network)
	}

	return udpConn, nil
}

// SO_REUSEPORT constant for Linux
const unixSO_REUSEPORT = 15
