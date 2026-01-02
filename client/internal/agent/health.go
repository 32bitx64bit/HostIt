package agent

import (
	"context"
	"sync"
	"time"
)

// HealthStatus represents the overall health of the agent.
type HealthStatus struct {
	Healthy           bool      `json:"healthy"`
	Connected         bool      `json:"connected"`
	LastConnected     time.Time `json:"last_connected,omitempty"`
	LastDisconnected  time.Time `json:"last_disconnected,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	LastErrorTime     time.Time `json:"last_error_time,omitempty"`
	ReconnectAttempts int       `json:"reconnect_attempts"`
	Uptime            string    `json:"uptime,omitempty"`
	CircuitState      string    `json:"circuit_state,omitempty"`
}

// HealthChecker provides health monitoring for the agent.
type HealthChecker struct {
	mu sync.RWMutex

	connected         bool
	lastConnected     time.Time
	lastDisconnected  time.Time
	lastError         string
	lastErrorTime     time.Time
	reconnectAttempts int
	startTime         time.Time
	circuitBreaker    *CircuitBreaker
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		startTime:      time.Now(),
		circuitBreaker: NewCircuitBreaker(),
	}
}

// SetConnected updates the connection status.
func (h *HealthChecker) SetConnected(connected bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	wasConnected := h.connected
	h.connected = connected

	if connected && !wasConnected {
		h.lastConnected = time.Now()
		h.reconnectAttempts = 0
		h.circuitBreaker.RecordSuccess()
	} else if !connected && wasConnected {
		h.lastDisconnected = time.Now()
	}
}

// RecordError records an error occurrence.
func (h *HealthChecker) RecordError(err error) {
	if err == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastError = err.Error()
	h.lastErrorTime = time.Now()
	h.circuitBreaker.RecordFailure()
}

// RecordReconnectAttempt increments the reconnect counter.
func (h *HealthChecker) RecordReconnectAttempt() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reconnectAttempts++
}

// ShouldAttemptReconnect returns true if a reconnection should be attempted.
func (h *HealthChecker) ShouldAttemptReconnect() bool {
	return h.circuitBreaker.AllowRequest()
}

// GetStatus returns the current health status.
func (h *HealthChecker) GetStatus() HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	uptime := ""
	if !h.startTime.IsZero() {
		uptime = time.Since(h.startTime).Round(time.Second).String()
	}

	return HealthStatus{
		Healthy:           h.connected,
		Connected:         h.connected,
		LastConnected:     h.lastConnected,
		LastDisconnected:  h.lastDisconnected,
		LastError:         h.lastError,
		LastErrorTime:     h.lastErrorTime,
		ReconnectAttempts: h.reconnectAttempts,
		Uptime:            uptime,
		CircuitState:      h.circuitBreaker.State(),
	}
}

// IsHealthy returns true if the agent is in a healthy state.
func (h *HealthChecker) IsHealthy() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.connected
}

// Reset resets all health metrics.
func (h *HealthChecker) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.connected = false
	h.lastConnected = time.Time{}
	h.lastDisconnected = time.Time{}
	h.lastError = ""
	h.lastErrorTime = time.Time{}
	h.reconnectAttempts = 0
	h.circuitBreaker.Reset()
}

// StartBackgroundHealthCheck starts a background goroutine that periodically
// checks connection health and can trigger reconnection if needed.
func (h *HealthChecker) StartBackgroundHealthCheck(ctx context.Context, checkInterval time.Duration, onUnhealthy func()) {
	if checkInterval < time.Second {
		checkInterval = 30 * time.Second
	}

	go func() {
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !h.IsHealthy() && onUnhealthy != nil {
					onUnhealthy()
				}
			}
		}
	}()
}
