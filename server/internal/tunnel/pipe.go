package tunnel

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

var copyBufPool = sync.Pool{New: func() any {
	// Larger buffer reduces syscall overhead on bulk transfers.
	return make([]byte, 256*1024)
}}

func copyOptimized(dst io.Writer, src io.Reader) (int64, error) {
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

func bidirPipeCount(a net.Conn, b net.Conn) (aToB int64, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	var n1 atomic.Int64
	var n2 atomic.Int64

	go func() {
		defer wg.Done()
		n, _ := copyOptimized(a, b)
		n1.Store(n)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		n, _ := copyOptimized(b, a)
		n2.Store(n)
		closeWrite(b)
	}()

	wg.Wait()
	_ = a.Close()
	_ = b.Close()

	return n1.Load(), n2.Load()
}

func bidirPipe(a net.Conn, b net.Conn) {
	_, _ = bidirPipeCount(a, b)
}
