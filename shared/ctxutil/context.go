package ctxutil

import (
	"context"
	"sync"
	"time"
)

// Keys for context values
type contextKey string

const (
	keyConnID    contextKey = "conn_id"
	keyRoute     contextKey = "route"
	keyRemoteIP  contextKey = "remote_ip"
	keyComponent contextKey = "component"
	keyStartTime contextKey = "start_time"
)

// WithConnID adds a connection ID to the context.
func WithConnID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyConnID, id)
}

// ConnID retrieves the connection ID from context.
func ConnID(ctx context.Context) string {
	if v, ok := ctx.Value(keyConnID).(string); ok {
		return v
	}
	return ""
}

// WithRoute adds a route name to the context.
func WithRoute(ctx context.Context, route string) context.Context {
	return context.WithValue(ctx, keyRoute, route)
}

// Route retrieves the route name from context.
func Route(ctx context.Context) string {
	if v, ok := ctx.Value(keyRoute).(string); ok {
		return v
	}
	return ""
}

// WithRemoteIP adds a remote IP to the context.
func WithRemoteIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, keyRemoteIP, ip)
}

// RemoteIP retrieves the remote IP from context.
func RemoteIP(ctx context.Context) string {
	if v, ok := ctx.Value(keyRemoteIP).(string); ok {
		return v
	}
	return ""
}

// WithComponent adds a component name to the context.
func WithComponent(ctx context.Context, component string) context.Context {
	return context.WithValue(ctx, keyComponent, component)
}

// Component retrieves the component name from context.
func Component(ctx context.Context) string {
	if v, ok := ctx.Value(keyComponent).(string); ok {
		return v
	}
	return ""
}

// WithStartTime adds a start time to the context.
func WithStartTime(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, keyStartTime, t)
}

// StartTime retrieves the start time from context.
func StartTime(ctx context.Context) time.Time {
	if v, ok := ctx.Value(keyStartTime).(time.Time); ok {
		return v
	}
	return time.Time{}
}

// Elapsed returns time since the context's start time.
func Elapsed(ctx context.Context) time.Duration {
	start := StartTime(ctx)
	if start.IsZero() {
		return 0
	}
	return time.Since(start)
}

// Fields extracts all context values as a map for logging.
func Fields(ctx context.Context) map[string]any {
	fields := make(map[string]any)
	if id := ConnID(ctx); id != "" {
		fields["conn_id"] = id
	}
	if route := Route(ctx); route != "" {
		fields["route"] = route
	}
	if ip := RemoteIP(ctx); ip != "" {
		fields["remote_ip"] = ip
	}
	if component := Component(ctx); component != "" {
		fields["component"] = component
	}
	if !StartTime(ctx).IsZero() {
		fields["elapsed_ms"] = Elapsed(ctx).Milliseconds()
	}
	return fields
}

// Merge merges multiple field maps into one.
func Merge(fieldMaps ...map[string]any) map[string]any {
	result := make(map[string]any)
	for _, m := range fieldMaps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// CancelGroup manages a group of cancellable contexts.
type CancelGroup struct {
	mu      sync.Mutex
	cancels []context.CancelFunc
	done    bool
}

// NewCancelGroup creates a new cancel group.
func NewCancelGroup() *CancelGroup {
	return &CancelGroup{
		cancels: make([]context.CancelFunc, 0),
	}
}

// Add creates a new cancellable context and tracks its cancel function.
func (g *CancelGroup) Add(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	
	g.mu.Lock()
	if g.done {
		g.mu.Unlock()
		cancel()
		return ctx, cancel
	}
	g.cancels = append(g.cancels, cancel)
	g.mu.Unlock()
	
	return ctx, cancel
}

// CancelAll cancels all tracked contexts.
func (g *CancelGroup) CancelAll() {
	g.mu.Lock()
	g.done = true
	cancels := g.cancels
	g.cancels = nil
	g.mu.Unlock()
	
	for _, cancel := range cancels {
		cancel()
	}
}

// TimeoutGroup manages operations with a shared deadline.
type TimeoutGroup struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	errMu  sync.Mutex
	err    error
}

// NewTimeoutGroup creates a group with a timeout.
func NewTimeoutGroup(parent context.Context, timeout time.Duration) *TimeoutGroup {
	ctx, cancel := context.WithTimeout(parent, timeout)
	return &TimeoutGroup{
		ctx:    ctx,
		cancel: cancel,
	}
}

// Context returns the group's context.
func (g *TimeoutGroup) Context() context.Context {
	return g.ctx
}

// Go runs a function in a goroutine, tracking it for Wait.
func (g *TimeoutGroup) Go(fn func(ctx context.Context) error) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		if err := fn(g.ctx); err != nil {
			g.errMu.Lock()
			if g.err == nil {
				g.err = err
			}
			g.errMu.Unlock()
		}
	}()
}

// Wait waits for all goroutines to complete and returns the first error.
func (g *TimeoutGroup) Wait() error {
	g.wg.Wait()
	g.cancel()
	return g.err
}

// Done returns whether the group's context is done.
func (g *TimeoutGroup) Done() bool {
	select {
	case <-g.ctx.Done():
		return true
	default:
		return false
	}
}

// AfterFunc runs a function after the context is canceled.
// Returns a stop function to prevent the callback from running.
func AfterFunc(ctx context.Context, fn func()) func() bool {
	stopCh := make(chan struct{})
	stopped := false
	var mu sync.Mutex

	go func() {
		select {
		case <-ctx.Done():
			mu.Lock()
			if !stopped {
				fn()
			}
			mu.Unlock()
		case <-stopCh:
			return
		}
	}()

	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return false
		}
		stopped = true
		close(stopCh)
		return true
	}
}

// WithCancelCause creates a context that can be canceled with a specific error.
// This is a compatibility wrapper for Go versions without context.WithCancelCause.
type CancelCauseFunc func(cause error)

func WithCancelCause(parent context.Context) (context.Context, CancelCauseFunc) {
	ctx, cancel := context.WithCancel(parent)
	var cause error
	var mu sync.Mutex
	
	cancelWithCause := func(err error) {
		mu.Lock()
		if cause == nil {
			cause = err
		}
		mu.Unlock()
		cancel()
	}
	
	return ctx, cancelWithCause
}
