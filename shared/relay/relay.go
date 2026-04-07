package relay

import (
	"errors"
	"io"
	"net"
	"sync"
)

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

func Proxy(a, b net.Conn) {
	if a == nil || b == nil {
		if a != nil {
			_ = a.Close()
		}
		if b != nil {
			_ = b.Close()
		}
		return
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
