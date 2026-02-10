//go:build !linux

package agent

import "net"

func trySetUDPBuffers(conn *net.UDPConn, size int) (actualRead, actualWrite int) {
	_ = conn.SetReadBuffer(size)
	_ = conn.SetWriteBuffer(size)
	return size, size
}
