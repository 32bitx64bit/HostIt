package connutil

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

// ErrConnectionDead indicates the connection is no longer usable.
var ErrConnectionDead = errors.New("connection is dead")

// ErrValidationTimeout indicates the validation check timed out.
var ErrValidationTimeout = errors.New("connection validation timed out")

// Validator provides connection health checking.
type Validator struct {
	timeout time.Duration
}

// NewValidator creates a connection validator with the specified timeout.
func NewValidator(timeout time.Duration) *Validator {
	if timeout <= 0 {
		timeout = time.Second
	}
	return &Validator{timeout: timeout}
}

// IsAlive checks if a TCP connection is still alive.
// This performs a non-blocking check without sending data.
func (v *Validator) IsAlive(conn net.Conn) bool {
	if conn == nil {
		return false
	}

	// Try to get the underlying TCP connection
	tc := unwrapTCPConn(conn)
	if tc == nil {
		// Can't get TCP conn, assume alive and let actual I/O fail
		return true
	}

	// Get the raw connection for syscall access
	raw, err := tc.SyscallConn()
	if err != nil {
		return false
	}

	alive := true
	err = raw.Read(func(fd uintptr) bool {
		// Peek at the socket to check for errors or closed state
		// Using a zero-length read with MSG_PEEK
		var buf [1]byte
		n, _, errno := syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		
		if errno != nil {
			if errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK {
				// No data available, but connection is alive
				return true
			}
			// Connection error
			alive = false
			return true
		}
		
		if n == 0 {
			// EOF - connection closed by peer
			alive = false
		}
		return true
	})

	if err != nil {
		return false
	}
	return alive
}

// ValidateWithRead validates a connection by attempting a read with a timeout.
// This is more reliable but requires setting deadlines.
func (v *Validator) ValidateWithRead(conn net.Conn) error {
	if conn == nil {
		return ErrConnectionDead
	}

	// Set a short read deadline
	oldDeadline := time.Time{}
	if err := conn.SetReadDeadline(time.Now().Add(v.timeout)); err != nil {
		return err
	}
	defer conn.SetReadDeadline(oldDeadline)

	// Try to read - we expect a timeout (no data available) for a healthy connection
	var buf [1]byte
	_, err := conn.Read(buf[:])
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout is expected - connection is alive but no data
			return nil
		}
		return ErrConnectionDead
	}

	// If we got data, that's unexpected for a pooled connection
	// The connection might be in a bad state
	return ErrConnectionDead
}

// unwrapTCPConn extracts the underlying *net.TCPConn from a connection.
func unwrapTCPConn(conn net.Conn) *net.TCPConn {
	if conn == nil {
		return nil
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc
	}
	// Try to unwrap from TLS or other wrapper
	if nc, ok := conn.(interface{ NetConn() net.Conn }); ok {
		return unwrapTCPConn(nc.NetConn())
	}
	return nil
}

// HealthChecker periodically validates connections in a pool.
type HealthChecker struct {
	mu        sync.RWMutex
	validator *Validator
	interval  time.Duration
	onDead    func(conn net.Conn)
	stop      chan struct{}
	conns     map[net.Conn]struct{}
}

// NewHealthChecker creates a background health checker.
func NewHealthChecker(interval time.Duration, onDead func(conn net.Conn)) *HealthChecker {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &HealthChecker{
		validator: NewValidator(time.Second),
		interval:  interval,
		onDead:    onDead,
		stop:      make(chan struct{}),
		conns:     make(map[net.Conn]struct{}),
	}
}

// Track adds a connection to be monitored.
func (h *HealthChecker) Track(conn net.Conn) {
	h.mu.Lock()
	h.conns[conn] = struct{}{}
	h.mu.Unlock()
}

// Untrack removes a connection from monitoring.
func (h *HealthChecker) Untrack(conn net.Conn) {
	h.mu.Lock()
	delete(h.conns, conn)
	h.mu.Unlock()
}

// Start begins the background health checking.
func (h *HealthChecker) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(h.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-h.stop:
				return
			case <-ticker.C:
				h.checkAll()
			}
		}
	}()
}

// Stop stops the background health checking.
func (h *HealthChecker) Stop() {
	close(h.stop)
}

func (h *HealthChecker) checkAll() {
	h.mu.RLock()
	conns := make([]net.Conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.RUnlock()

	for _, conn := range conns {
		if !h.validator.IsAlive(conn) {
			h.mu.Lock()
			delete(h.conns, conn)
			h.mu.Unlock()
			if h.onDead != nil {
				h.onDead(conn)
			}
		}
	}
}

// TrackedCount returns the number of currently tracked connections.
func (h *HealthChecker) TrackedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}

// ConnWithContext wraps a connection with context cancellation support.
type ConnWithContext struct {
	net.Conn
	ctx    context.Context
	cancel context.CancelFunc
}

// WrapWithContext wraps a connection to respect context cancellation.
func WrapWithContext(ctx context.Context, conn net.Conn) *ConnWithContext {
	ctx, cancel := context.WithCancel(ctx)
	c := &ConnWithContext{
		Conn:   conn,
		ctx:    ctx,
		cancel: cancel,
	}

	// Monitor context and close connection when canceled
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	return c
}

// Context returns the connection's context.
func (c *ConnWithContext) Context() context.Context {
	return c.ctx
}

// Close closes the connection and cancels the context.
func (c *ConnWithContext) Close() error {
	c.cancel()
	return c.Conn.Close()
}
