//go:build !linux

package udputil

import (
	"net"
)

// GSO/GRO are Linux-specific features. This file provides stubs for other platforms.

// CheckGSOSupport returns false on non-Linux platforms.
func CheckGSOSupport() bool {
	return false
}

// CheckGROSupport returns false on non-Linux platforms.
func CheckGROSupport() bool {
	return false
}

// IsGSOEnabled returns false on non-Linux platforms.
func IsGSOEnabled() bool {
	return false
}

// IsGROEnabled returns false on non-Linux platforms.
func IsGROEnabled() bool {
	return false
}

// SetGSOSegmentSize is a no-op on non-Linux platforms.
func SetGSOSegmentSize(size int) {}

// EnableGSO is a no-op on non-Linux platforms.
func EnableGSO(conn *net.UDPConn) error {
	return nil
}

// EnableGRO is a no-op on non-Linux platforms.
func EnableGRO(conn *net.UDPConn) error {
	return nil
}

// SendWithGSO falls back to regular send on non-Linux platforms.
func SendWithGSO(conn *net.UDPConn, data []byte, segmentSize int, addr *net.UDPAddr) (int, error) {
	_, err := conn.WriteToUDP(data, addr)
	return 1, err
}

// RecvWithGRO uses regular receive on non-Linux platforms.
func RecvWithGRO(conn *net.UDPConn, buf []byte) (int, *net.UDPAddr, error) {
	return conn.ReadFromUDP(buf)
}

// GSOStats tracks GSO/GRO statistics.
type GSOStats struct {
	GSOEnabled       bool
	GROEnabled       bool
	SegmentsSent     uint64
	BytesSent        uint64
	GROPacketsMerged uint64
}

// GetGSOStats returns current GSO/GRO statistics.
func GetGSOStats() GSOStats {
	return GSOStats{
		GSOEnabled: false,
		GROEnabled: false,
	}
}
