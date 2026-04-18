package relay

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.timeout))
	}
	return n, err
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.timeout))
	}
	return n, err
}

func Proxy(a, b net.Conn) {
	ProxyWithIdleTimeout(a, b, 0)
}

func ProxyWithIdleTimeout(a, b net.Conn, idleTimeout time.Duration) {
	if a == nil || b == nil {
		if a != nil {
			_ = a.Close()
		}
		if b != nil {
			_ = b.Close()
		}
		return
	}

	if idleTimeout > 0 {
		now := time.Now()
		a.SetDeadline(now.Add(idleTimeout))
		b.SetDeadline(now.Add(idleTimeout))
		a = &idleTimeoutConn{Conn: a, timeout: idleTimeout}
		b = &idleTimeoutConn{Conn: b, timeout: idleTimeout}
	}

	var (
		wg        sync.WaitGroup
		closeOnce sync.Once
	)

	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}

	pipe := func(dst, src net.Conn) {
		defer wg.Done()

		buf := make([]byte, 32*1024)
		_, err := io.CopyBuffer(dst, src, buf)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			closeOnce.Do(closeBoth)
			return
		}

		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			closeOnce.Do(closeBoth)
			return
		}

		if cr, ok := src.(closeReader); ok {
			_ = cr.CloseRead()
		}
	}

	wg.Add(2)
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
	closeOnce.Do(closeBoth)
}
