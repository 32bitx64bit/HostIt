package agent

import (
	"testing"
	"time"
)

func TestCircuitBreaker_StartsClosedAllowsRequests(t *testing.T) {
	cb := NewCircuitBreaker()
	
	if cb.State() != "closed" {
		t.Errorf("expected closed state, got %s", cb.State())
	}
	
	if !cb.AllowRequest() {
		t.Error("expected requests to be allowed in closed state")
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(3, 2, 100*time.Millisecond)
	
	// Record failures up to threshold
	cb.RecordFailure()
	cb.RecordFailure()
	
	if cb.State() != "closed" {
		t.Errorf("expected closed state after 2 failures, got %s", cb.State())
	}
	
	cb.RecordFailure() // Third failure should open circuit
	
	if cb.State() != "open" {
		t.Errorf("expected open state after 3 failures, got %s", cb.State())
	}
	
	if cb.AllowRequest() {
		t.Error("expected requests to be blocked in open state")
	}
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(1, 1, 10*time.Millisecond)
	
	cb.RecordFailure() // Open the circuit
	
	if cb.State() != "open" {
		t.Fatalf("expected open state, got %s", cb.State())
	}
	
	// Wait for open duration to pass (with large margin)
	time.Sleep(100 * time.Millisecond)
	
	// Next AllowRequest should transition to half-open
	if !cb.AllowRequest() {
		t.Error("expected request to be allowed after open duration")
	}
	
	if cb.State() != "half-open" {
		t.Errorf("expected half-open state, got %s", cb.State())
	}
}

func TestCircuitBreaker_ClosesAfterSuccessInHalfOpen(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(1, 2, 10*time.Millisecond)
	
	cb.RecordFailure() // Open
	time.Sleep(100 * time.Millisecond) // Ensure we pass open duration
	
	if !cb.AllowRequest() { // Transition to half-open
		t.Fatal("expected AllowRequest to succeed and transition to half-open")
	}
	
	if cb.State() != "half-open" {
		t.Fatalf("expected half-open state, got %s", cb.State())
	}
	
	cb.RecordSuccess()
	if cb.State() != "half-open" {
		t.Errorf("expected half-open state after 1 success, got %s", cb.State())
	}
	
	cb.RecordSuccess()
	if cb.State() != "closed" {
		t.Errorf("expected closed state after 2 successes, got %s", cb.State())
	}
}

func TestCircuitBreaker_ReopensOnHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(1, 2, 10*time.Millisecond)
	
	cb.RecordFailure() // Open
	time.Sleep(100 * time.Millisecond) // Ensure we pass open duration
	
	if !cb.AllowRequest() { // Transition to half-open
		t.Fatal("expected AllowRequest to succeed")
	}
	
	if cb.State() != "half-open" {
		t.Fatalf("expected half-open state, got %s", cb.State())
	}
	
	cb.RecordFailure() // Should go back to open
	
	if cb.State() != "open" {
		t.Errorf("expected open state after failure in half-open, got %s", cb.State())
	}
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(3, 1, 100*time.Millisecond)
	
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // Should reset count
	cb.RecordFailure()
	cb.RecordFailure()
	
	// Should still be closed because success reset the count
	if cb.State() != "closed" {
		t.Errorf("expected closed state, got %s", cb.State())
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	cb := NewCircuitBreakerWithConfig(1, 1, 100*time.Millisecond)
	
	cb.RecordFailure() // Open
	
	if cb.State() != "open" {
		t.Fatalf("expected open state, got %s", cb.State())
	}
	
	cb.Reset()
	
	if cb.State() != "closed" {
		t.Errorf("expected closed state after reset, got %s", cb.State())
	}
	
	if !cb.AllowRequest() {
		t.Error("expected requests to be allowed after reset")
	}
}

func TestHealthChecker_TracksConnectionState(t *testing.T) {
	h := NewHealthChecker()
	
	status := h.GetStatus()
	if status.Connected {
		t.Error("expected not connected initially")
	}
	
	h.SetConnected(true)
	status = h.GetStatus()
	if !status.Connected {
		t.Error("expected connected after SetConnected(true)")
	}
	if status.LastConnected.IsZero() {
		t.Error("expected LastConnected to be set")
	}
	
	h.SetConnected(false)
	status = h.GetStatus()
	if status.Connected {
		t.Error("expected not connected after SetConnected(false)")
	}
	if status.LastDisconnected.IsZero() {
		t.Error("expected LastDisconnected to be set")
	}
}

func TestHealthChecker_TracksErrors(t *testing.T) {
	h := NewHealthChecker()
	
	h.RecordError(nil) // Should be ignored
	status := h.GetStatus()
	if status.LastError != "" {
		t.Error("expected no error recorded for nil")
	}
	
	h.RecordError(&testError{msg: "test error"})
	status = h.GetStatus()
	if status.LastError != "test error" {
		t.Errorf("expected 'test error', got %s", status.LastError)
	}
}

func TestHealthChecker_ReconnectAttempts(t *testing.T) {
	h := NewHealthChecker()
	
	h.RecordReconnectAttempt()
	h.RecordReconnectAttempt()
	h.RecordReconnectAttempt()
	
	status := h.GetStatus()
	if status.ReconnectAttempts != 3 {
		t.Errorf("expected 3 reconnect attempts, got %d", status.ReconnectAttempts)
	}
	
	h.SetConnected(true) // Should reset attempts
	status = h.GetStatus()
	if status.ReconnectAttempts != 0 {
		t.Errorf("expected 0 reconnect attempts after connect, got %d", status.ReconnectAttempts)
	}
}

func TestHealthChecker_CircuitBreakerIntegration(t *testing.T) {
	h := NewHealthChecker()
	
	// Fill up failures to open circuit
	for i := 0; i < 5; i++ {
		h.RecordError(&testError{msg: "failure"})
	}
	
	status := h.GetStatus()
	if status.CircuitState != "open" {
		t.Errorf("expected circuit to be open, got %s", status.CircuitState)
	}
	
	if h.ShouldAttemptReconnect() {
		t.Error("expected reconnect to be blocked when circuit is open")
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
