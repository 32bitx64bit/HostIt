package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

const defaultIdleTimeout = 5 * time.Second

func Proxy(a, b net.Conn) {
	ProxyWithIdleTimeout(a, b, defaultIdleTimeout)
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		wg        sync.WaitGroup
		closeOnce sync.Once
		lastRead  = time.Now().UnixNano()
		mu        sync.Mutex
	)

	closeBoth := func() {
		cancel()
		_ = a.Close()
		_ = b.Close()
	}

	updateLastRead := func() {
		mu.Lock()
		lastRead = time.Now().UnixNano()
		mu.Unlock()
	}

	pipe := func(dst, src net.Conn) {
		defer wg.Done()

		buf := make([]byte, 32*1024)
		for {
			src.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				updateLastRead()
				writeN, writeErr := dst.Write(buf[:n])
				if writeErr != nil || writeN != n {
					closeOnce.Do(closeBoth)
					return
				}
				if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
			}
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					closeOnce.Do(closeBoth)
					return
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if !errors.Is(err, io.EOF) {
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
				return
			}
		}
	}

	wg.Add(2)
	go pipe(a, b)
	go pipe(b, a)

	go func() {
		ticker := time.NewTicker(idleTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				last := lastRead
				mu.Unlock()
				if time.Since(time.Unix(0, last)) > idleTimeout {
					closeOnce.Do(closeBoth)
					return
				}
			}
		}
	}()

	wg.Wait()
	closeOnce.Do(closeBoth)
}
