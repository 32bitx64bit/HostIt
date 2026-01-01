package agent

import (
	"io"
	"net"
	"sync"
)

var copyBufPool = sync.Pool{New: func() any {
	// Larger buffer reduces syscall overhead on bulk transfers.
	// 512KB provides a good balance for high-throughput scenarios.
	return make([]byte, 512*1024)
}}

func copyOptimized(dst io.Writer, src io.Reader) (int64, error) {
	// Note: WriterTo/ReaderFrom checks are kept for raw TCP connections
	// but TLS connections don't implement these interfaces, so they'll
	// use the buffer path. The larger buffer size compensates.
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	if rf, ok := dst.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	buf := copyBufPool.Get().([]byte)
	n, err := io.CopyBuffer(dst, src, buf)
	copyBufPool.Put(buf)
	return n, err
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func closeRead(c net.Conn) {
	if cr, ok := c.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
		return
	}
}

func bidirPipeCount(a net.Conn, b net.Conn) (aToB int64, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	var once sync.Once
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}

	var n1, n2 int64

	go func() {
		defer wg.Done()
		n1, _ = copyOptimized(a, b)
		closeRead(b)
		closeWrite(a)
		once.Do(closeBoth)
	}()
	go func() {
		defer wg.Done()
		n2, _ = copyOptimized(b, a)
		closeRead(a)
		closeWrite(b)
		once.Do(closeBoth)
	}()

	wg.Wait()
	once.Do(closeBoth)

	return n1, n2
}

func bidirPipe(a net.Conn, b net.Conn) {
	_, _ = bidirPipeCount(a, b)
}
