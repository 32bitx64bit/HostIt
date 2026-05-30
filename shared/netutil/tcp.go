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

// SetTCPNoDelay disables Nagle's algorithm on the underlying TCP connection so
// small writes are sent immediately instead of being coalesced. This lowers
// latency for interactive/relayed traffic without affecting bulk throughput.
// It returns true when the option was applied to an underlying *net.TCPConn.
func SetTCPNoDelay(conn net.Conn) bool {
	tcpConn := UnwrapTCPConn(conn)
	if tcpConn == nil {
		return false
	}
	_ = tcpConn.SetNoDelay(true)
	return true
}

// WriteAll writes all of b to w, looping over partial writes until the buffer
// is fully drained or an error occurs. It returns io.ErrShortWrite if the
// writer reports zero bytes written without an error.
func WriteAll(w io.Writer, b []byte) (int, error) {
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

// CloseWrite half-closes the write side of conn if the connection (or an
// underlying connection reachable via NetConn) supports it. When no half-close
// is available it falls back to closing the whole connection.
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

// CloseRead half-closes the read side of conn if supported, otherwise closes
// the whole connection.
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
