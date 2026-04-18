package netutil

import (
	"net"
	"time"
)

func SetTCPKeepAlive(conn net.Conn, period time.Duration) {
	if period <= 0 || conn == nil {
		return
	}
	tcpConn := UnwrapTCPConn(conn)
	if tcpConn == nil {
		return
	}
	_ = tcpConn.SetKeepAlive(true)
	_ = tcpConn.SetKeepAlivePeriod(period)
}

func UnwrapTCPConn(conn net.Conn) *net.TCPConn {
	return unwrapTCPConn(conn, 16)
}

func unwrapTCPConn(conn net.Conn, depth int) *net.TCPConn {
	if conn == nil || depth <= 0 {
		return nil
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		return tcpConn
	}
	type netConner interface{ NetConn() net.Conn }
	if wrapped, ok := conn.(netConner); ok {
		next := wrapped.NetConn()
		if next == nil || next == conn {
			return nil
		}
		return unwrapTCPConn(next, depth-1)
	}
	return nil
}
