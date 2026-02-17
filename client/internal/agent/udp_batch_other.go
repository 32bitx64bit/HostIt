//go:build !linux

package agent

import (
	"net"
)

// sendmmsgBatch sends multiple packets, falling back to individual sends on non-Linux.
// Returns the number of packets successfully sent and any error.
func sendmmsgBatch(conn *net.UDPConn, packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	sent := 0
	for _, pkt := range packets {
		_, err := conn.Write(pkt)
		if err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// sendmmsg is a stub for non-Linux platforms that falls back to individual sends.
// Returns the number of packets successfully sent and any error.
func sendmmsg(conn *net.UDPConn, packets [][]byte, addrs []*net.UDPAddr) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}

	sent := 0
	for i, pkt := range packets {
		var err error
		if addrs[i] != nil {
			_, err = conn.WriteToUDP(pkt, addrs[i])
		} else {
			_, err = conn.Write(pkt)
		}
		if err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// recvmmsg is a stub for non-Linux platforms that falls back to individual receives.
// Returns the number of packets received, the actual sizes, and any error.
func recvmmsg(conn *net.UDPConn, buffers [][]byte) (int, []int, []*net.UDPAddr, error) {
	if len(buffers) == 0 {
		return 0, nil, nil, nil
	}

	sizes := make([]int, len(buffers))
	addrs := make([]*net.UDPAddr, len(buffers))

	for i, buf := range buffers {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return i, sizes[:i], addrs[:i], err
		}
		sizes[i] = n
		addrs[i] = addr
	}
	return len(buffers), sizes, addrs, nil
}
