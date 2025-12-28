package tunnel

import (
	"io"
	"net"
	"sync"
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

func bidirPipe(a net.Conn, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = copyOptimized(a, b)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = copyOptimized(b, a)
		closeWrite(b)
	}()

	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
