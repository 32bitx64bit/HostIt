//go:build !linux

package tunnel

import (
	"net"
)

// sendmmsgWriteTo sends multiple packets individually (non-Linux fallback).
func sendmmsgWriteTo(conn *net.UDPConn, packets [][]byte, addrs []*net.UDPAddr) (int, error) {
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

// sendmmsgBatch sends multiple packets on a connected socket (non-Linux fallback).
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

// sendmmsgPacketConn sends multiple packets via a PacketConn (non-Linux fallback).
func sendmmsgPacketConn(pc net.PacketConn, packets [][]byte, addrs []net.Addr) (int, error) {
	return sendIndividual(pc, packets, addrs)
}
