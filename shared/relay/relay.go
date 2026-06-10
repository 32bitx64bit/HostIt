package relay

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"hostit/shared/netutil"
)

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

var relayBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Refreshes read/write deadline on activity, throttled to once per threshold
// to avoid per-chunk syscalls.
type idleTimeoutConn struct {
	net.Conn
	timeout         time.Duration
	threshold       time.Duration
	lastRefreshNano int64 // atomic; UnixNano of the last SetDeadline call
}

func newIdleTimeoutConn(c net.Conn, timeout time.Duration) *idleTimeoutConn {
	threshold := timeout / 16
	if threshold <= 0 {
		threshold = timeout
	}
	now := time.Now()
	c.SetDeadline(now.Add(timeout))
	return &idleTimeoutConn{
		Conn:            c,
		timeout:         timeout,
		threshold:       threshold,
		lastRefreshNano: now.UnixNano(),
	}
}

func (c *idleTimeoutConn) refresh() {
	now := time.Now()
	nowNano := now.UnixNano()
	last := atomic.LoadInt64(&c.lastRefreshNano)
	if nowNano-last < int64(c.threshold) {
		return
	}
	// CAS ensures one syscall per window; the other direction is skipped.
	if atomic.CompareAndSwapInt64(&c.lastRefreshNano, last, nowNano) {
		c.Conn.SetDeadline(now.Add(c.timeout))
	}
}

// Expose CloseWrite/CloseRead so half-close works.
func (c *idleTimeoutConn) CloseWrite() error { return netutil.CloseWrite(c.Conn) }
func (c *idleTimeoutConn) CloseRead() error  { return netutil.CloseRead(c.Conn) }
func (c *idleTimeoutConn) NetConn() net.Conn { return c.Conn }

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.refresh()
	}
	return n, err
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.refresh()
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
		a = newIdleTimeoutConn(a, idleTimeout)
		b = newIdleTimeoutConn(b, idleTimeout)
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

		bufPtr := relayBufPool.Get().(*[]byte)
		buf := *bufPtr
		_, err := io.CopyBuffer(dst, src, buf)
		relayBufPool.Put(bufPtr)
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
