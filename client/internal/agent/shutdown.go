package agent

import (
	"context"
	"sync"
	"time"
)

// GracefulShutdown coordinates clean shutdown of agent components.
type GracefulShutdown struct {
	mu       sync.Mutex
	wg       sync.WaitGroup
	done     chan struct{}
	timeout  time.Duration
	shutdown bool
}

// NewGracefulShutdown creates a shutdown coordinator with the given timeout.
func NewGracefulShutdown(timeout time.Duration) *GracefulShutdown {
	if timeout < time.Second {
		timeout = 30 * time.Second
	}
	return &GracefulShutdown{
		done:    make(chan struct{}),
		timeout: timeout,
	}
}

// Add adds a component to track. Call Done() when the component finishes.
func (g *GracefulShutdown) Add(delta int) {
	g.wg.Add(delta)
}

// Done marks a component as finished.
func (g *GracefulShutdown) Done() {
	g.wg.Done()
}

// IsShuttingDown returns true if shutdown has been initiated.
func (g *GracefulShutdown) IsShuttingDown() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.shutdown
}

// Shutdown initiates graceful shutdown and waits for all components to finish
// or until the timeout is reached.
func (g *GracefulShutdown) Shutdown(ctx context.Context) error {
	g.mu.Lock()
	if g.shutdown {
		g.mu.Unlock()
		return nil
	}
	g.shutdown = true
	close(g.done)
	g.mu.Unlock()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	// Wait for all components or timeout
	waitCh := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done returns a channel that's closed when shutdown is initiated.
func (g *GracefulShutdown) ShutdownChan() <-chan struct{} {
	return g.done
}

// DrainConnections helps drain active connections during shutdown.
// It returns a context that will be cancelled after the drain period.
func DrainConnections(ctx context.Context, drainPeriod time.Duration) (context.Context, context.CancelFunc) {
	if drainPeriod < 0 {
		drainPeriod = 5 * time.Second
	}
	return context.WithTimeout(ctx, drainPeriod)
}

// WaitForActiveConnections is a helper to wait for active connections to drain.
// activeCount should return the current number of active connections.
// pollInterval determines how often to check.
func WaitForActiveConnections(ctx context.Context, activeCount func() int, pollInterval time.Duration) {
	if pollInterval < 10*time.Millisecond {
		pollInterval = 100 * time.Millisecond
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if activeCount() == 0 {
				return
			}
		}
	}
}
