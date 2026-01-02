package agent

import (
	"sync"
	"time"
)

// CircuitBreaker prevents repeated calls to failing operations.
// State transitions: Closed -> Open -> HalfOpen -> Closed/Open
type CircuitBreaker struct {
	mu sync.Mutex

	// Configuration
	failureThreshold int           // Failures before opening circuit
	successThreshold int           // Successes in half-open before closing
	openDuration     time.Duration // How long to stay open before half-open

	// State
	state            circuitState
	failures         int
	successes        int
	lastFailure      time.Time
	lastStateChange  time.Time
}

type circuitState int

const (
	circuitClosed   circuitState = iota // Normal operation
	circuitOpen                          // Failing, reject requests
	circuitHalfOpen                      // Testing if service recovered
)

// NewCircuitBreaker creates a circuit breaker with sensible defaults.
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: 5,
		successThreshold: 2,
		openDuration:     30 * time.Second,
		state:            circuitClosed,
		lastStateChange:  time.Now(),
	}
}

// NewCircuitBreakerWithConfig creates a circuit breaker with custom settings.
func NewCircuitBreakerWithConfig(failureThreshold, successThreshold int, openDuration time.Duration) *CircuitBreaker {
	if failureThreshold < 1 {
		failureThreshold = 5
	}
	if successThreshold < 1 {
		successThreshold = 2
	}
	// Allow short durations for testing, but enforce minimum of 1ms
	if openDuration < time.Millisecond {
		openDuration = 30 * time.Second
	}
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		openDuration:     openDuration,
		state:            circuitClosed,
		lastStateChange:  time.Now(),
	}
}

// AllowRequest returns true if a request should be attempted.
func (cb *CircuitBreaker) AllowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case circuitClosed:
		return true
	case circuitOpen:
		// Check if we should transition to half-open
		if time.Since(cb.lastStateChange) >= cb.openDuration {
			cb.state = circuitHalfOpen
			cb.lastStateChange = time.Now()
			cb.successes = 0
			return true
		}
		return false
	case circuitHalfOpen:
		return true
	default:
		return true
	}
}

// RecordSuccess records a successful operation.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case circuitHalfOpen:
		cb.successes++
		if cb.successes >= cb.successThreshold {
			cb.state = circuitClosed
			cb.lastStateChange = time.Now()
			cb.failures = 0
			cb.successes = 0
		}
	case circuitClosed:
		cb.failures = 0 // Reset failure count on success
	}
}

// RecordFailure records a failed operation.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailure = time.Now()

	switch cb.state {
	case circuitClosed:
		cb.failures++
		if cb.failures >= cb.failureThreshold {
			cb.state = circuitOpen
			cb.lastStateChange = time.Now()
		}
	case circuitHalfOpen:
		// Any failure in half-open goes back to open
		cb.state = circuitOpen
		cb.lastStateChange = time.Now()
		cb.successes = 0
	}
}

// State returns the current circuit state as a string.
func (cb *CircuitBreaker) State() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case circuitClosed:
		return "closed"
	case circuitOpen:
		return "open"
	case circuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Stats returns current circuit breaker statistics.
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return CircuitBreakerStats{
		State:           cb.state,
		Failures:        cb.failures,
		Successes:       cb.successes,
		LastFailure:     cb.lastFailure,
		LastStateChange: cb.lastStateChange,
	}
}

type CircuitBreakerStats struct {
	State           circuitState
	Failures        int
	Successes       int
	LastFailure     time.Time
	LastStateChange time.Time
}

// Reset forces the circuit breaker back to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = circuitClosed
	cb.failures = 0
	cb.successes = 0
	cb.lastStateChange = time.Now()
}
