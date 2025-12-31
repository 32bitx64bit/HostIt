package lineproto

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

var ErrClosed = errors.New("connection closed")

type RW struct {
	r  *bufio.Reader
	w  *bufio.Writer
	mu sync.Mutex
}

func New(r io.Reader, w io.Writer) *RW {
	return &RW{
		r: bufio.NewReaderSize(r, 32*1024),
		w: bufio.NewWriterSize(w, 32*1024),
	}
}

func (rw *RW) ReadLine() (string, error) {
	line, err := rw.r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", ErrClosed
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (rw *RW) WriteLinef(format string, args ...any) error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if _, err := fmt.Fprintf(rw.w, format+"\n", args...); err != nil {
		return err
	}
	return rw.w.Flush()
}

func Split2(line string) (cmd string, rest string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.TrimSpace(parts[1])
}
