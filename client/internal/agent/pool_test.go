package agent

import (
	"net"
	"testing"
	"time"
)

func TestDataConnPool_DiscardStale(t *testing.T) {
	p := &dataConnPool{
		ch:       make(chan net.Conn, 1),
		capacity: 1,
	}
	c1, c2 := net.Pipe()
	defer c2.Close()

	p.createdAt.Store(c1, time.Now().Add(-2*poolConnMaxAge))
	p.size.Add(1)
	p.ch <- c1

	got := p.tryGet()
	if got != nil {
		_ = got.Close()
		t.Fatalf("expected stale conn to be discarded")
	}

	if p.size.Load() != 0 {
		t.Fatalf("expected pool size 0, got %d", p.size.Load())
	}
}
