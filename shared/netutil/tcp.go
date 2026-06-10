package netutil

import (
	"io"
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

// Dead-peer detection defaults. A relayed connection whose remote peer
// vanishes without a clean TCP shutdown must be reaped quickly so the
// relay tears down both legs. Without this, connections "stack" until
// restart.
const (
	deadPeerKeepAliveIdle     = 10 * time.Second
	deadPeerKeepAliveInterval = 5 * time.Second
	deadPeerKeepAliveCount    = 3
	deadPeerUserTimeout       = 20 * time.Second
)

// SetTCPKeepAliveConfig enables keepalive with an explicit idle/interval/count.
// It is a no-op for non-TCP connections or when the platform rejects the
// configuration.
func SetTCPKeepAliveConfig(conn net.Conn, idle, interval time.Duration, count int) {
	tcpConn := UnwrapTCPConn(conn)
	if tcpConn == nil {
		return
	}
	_ = tcpConn.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     idle,
		Interval: interval,
		Count:    count,
	})
}

// TuneDeadPeerDetection applies aggressive keepalive plus TCP_USER_TIMEOUT
// (on supported platforms) so a silently vanished peer is reset quickly.
// Keepalive handles the idle-but-dead case; TCP_USER_TIMEOUT handles the
// case where the relay is pushing to a peer that stopped acknowledging.
// Safe to call on any net.Conn; no-op for non-TCP connections.
func TuneDeadPeerDetection(conn net.Conn) {
	SetTCPKeepAliveConfig(conn, deadPeerKeepAliveIdle, deadPeerKeepAliveInterval, deadPeerKeepAliveCount)
	_ = SetTCPUserTimeout(conn, deadPeerUserTimeout)
}

// SetTCPNoDelay disables Nagle's algorithm so small writes are sent
// immediately. It returns true when applied to an underlying *net.TCPConn.
func SetTCPNoDelay(conn net.Conn) bool {
	tcpConn := UnwrapTCPConn(conn)
	if tcpConn == nil {
		return false
	}
	_ = tcpConn.SetNoDelay(true)
	return true
}

// WriteAll writes all of b to w, looping over partial writes. For *net.TCPConn
// and related stdlib types, the standard library already loops on short writes,
// so we skip our outer loop and call Write once.
func WriteAll(w io.Writer, b []byte) (int, error) {
	switch w.(type) {
	case *net.TCPConn, *net.UDPConn, *net.UnixConn, *net.IPConn:
		return w.Write(b)
	}
	total := 0
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > 0 {
			total += n
			b = b[n:]
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

// CloseWrite half-closes the write side of conn if supported. Falls back to
// closing the whole connection when half-close is unavailable.
func CloseWrite(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	if tcp := UnwrapTCPConn(conn); tcp != nil {
		return tcp.CloseWrite()
	}
	return conn.Close()
}

// CloseRead half-closes the read side of conn if supported. Falls back to
// closing the whole connection.
func CloseRead(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	if cr, ok := conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	if tcp := UnwrapTCPConn(conn); tcp != nil {
		return tcp.CloseRead()
	}
	return conn.Close()
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
