//go:build !linux

package tunnel

import "net"

// trySetUDPBuffers sets UDP socket buffers and returns the requested size
// as the "actual" size (no verification available on non-Linux platforms).
func trySetUDPBuffers(conn *net.UDPConn, size int) (actualRead, actualWrite int) {
	_ = conn.SetReadBuffer(size)
	_ = conn.SetWriteBuffer(size)
	return size, size
}
