package agent

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type agentCloseTrackingConn struct {
	mu       sync.Mutex
	closed   bool
	closedCh chan struct{}
}

func newAgentCloseTrackingConn() *agentCloseTrackingConn {
	return &agentCloseTrackingConn{closedCh: make(chan struct{})}
}

func (c *agentCloseTrackingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *agentCloseTrackingConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *agentCloseTrackingConn) LocalAddr() net.Addr              { return agentDummyAddr("local") }
func (c *agentCloseTrackingConn) RemoteAddr() net.Addr             { return agentDummyAddr("remote") }
func (c *agentCloseTrackingConn) SetDeadline(time.Time) error      { return nil }
func (c *agentCloseTrackingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *agentCloseTrackingConn) SetWriteDeadline(time.Time) error { return nil }

func (c *agentCloseTrackingConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	close(c.closedCh)
	return nil
}

type agentDummyAddr string

func (d agentDummyAddr) Network() string { return "tcp" }
func (d agentDummyAddr) String() string  { return string(d) }

func waitAgentConnClosed(t *testing.T, conn *agentCloseTrackingConn, name string) {
	t.Helper()
	select {
	case <-conn.closedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s was not closed", name)
	}
}

func assertAgentConnOpen(t *testing.T, conn *agentCloseTrackingConn, name string) {
	t.Helper()
	select {
	case <-conn.closedCh:
		t.Fatalf("%s was closed", name)
	default:
	}
}

func TestConnTrackerCloseAllClosesTrackedConnections(t *testing.T) {
	tracker := &connTracker{}
	first := newAgentCloseTrackingConn()
	second := newAgentCloseTrackingConn()

	tracker.add(first)
	tracker.add(second)
	tracker.closeAll()
	tracker.closeAll()

	waitAgentConnClosed(t, first, "first tracked connection")
	waitAgentConnClosed(t, second, "second tracked connection")
}

func TestConnTrackerRemovePreventsCloseAll(t *testing.T) {
	tracker := &connTracker{}
	tracked := newAgentCloseTrackingConn()
	removed := newAgentCloseTrackingConn()

	tracker.add(tracked)
	tracker.add(removed)
	tracker.remove(removed)
	tracker.closeAll()

	waitAgentConnClosed(t, tracked, "tracked connection")
	assertAgentConnOpen(t, removed, "removed connection")
}

func TestConnTrackerAddAfterCloseClosesImmediately(t *testing.T) {
	tracker := &connTracker{}
	tracker.closeAll()

	late := newAgentCloseTrackingConn()
	tracker.add(late)

	waitAgentConnClosed(t, late, "late connection")
}
