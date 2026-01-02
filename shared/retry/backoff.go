package retry

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"sync"
	"time"
)

// ErrMaxRetriesExceeded is returned when the maximum retry count is reached.
var ErrMaxRetriesExceeded = errors.New("maximum retries exceeded")

// ErrContextCanceled is returned when the context is canceled during retry.
var ErrContextCanceled = errors.New("context canceled during retry")

// Config holds retry configuration.
type Config struct {
	// InitialDelay is the delay before the first retry.
	InitialDelay time.Duration
	// MaxDelay is the maximum delay between retries.
	MaxDelay time.Duration
	// Multiplier is the factor by which the delay increases after each retry.
	Multiplier float64
	// MaxRetries is the maximum number of retry attempts. 0 means infinite.
	MaxRetries int
	// JitterFactor is the fraction of the delay to randomize (0.0 to 1.0).
	// For example, 0.25 means ±25% jitter.
	JitterFactor float64
	// RetryIf is an optional function that determines if an error is retryable.
	// If nil, all errors are considered retryable.
	RetryIf func(error) bool
}

// DefaultConfig returns a sensible default retry configuration.
func DefaultConfig() Config {
	return Config{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		MaxRetries:   10,
		JitterFactor: 0.25,
	}
}

// AggressiveConfig returns a config for situations needing fast recovery.
func AggressiveConfig() Config {
	return Config{
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     5 * time.Second,
		Multiplier:   1.5,
		MaxRetries:   20,
		JitterFactor: 0.3,
	}
}

// ConservativeConfig returns a config for situations needing less aggressive retry.
func ConservativeConfig() Config {
	return Config{
		InitialDelay: 500 * time.Millisecond,
		MaxDelay:     60 * time.Second,
		Multiplier:   2.0,
		MaxRetries:   5,
		JitterFactor: 0.25,
	}
}

// Backoff calculates the next backoff duration with jitter.
type Backoff struct {
	cfg     Config
	attempt int
	rng     *rand.Rand
	mu      sync.Mutex
}

// NewBackoff creates a new Backoff calculator.
func NewBackoff(cfg Config) *Backoff {
	if cfg.InitialDelay <= 0 {
		cfg.InitialDelay = 100 * time.Millisecond
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 30 * time.Second
	}
	if cfg.Multiplier <= 0 {
		cfg.Multiplier = 2.0
	}
	if cfg.JitterFactor < 0 {
		cfg.JitterFactor = 0
	}
	if cfg.JitterFactor > 1 {
		cfg.JitterFactor = 1
	}

	return &Backoff{
		cfg:     cfg,
		attempt: 0,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Next returns the next backoff duration and increments the attempt counter.
// Returns the duration and true if retry should proceed, or 0 and false if max retries exceeded.
func (b *Backoff) Next() (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cfg.MaxRetries > 0 && b.attempt >= b.cfg.MaxRetries {
		return 0, false
	}

	delay := b.calculateDelay()
	b.attempt++
	return delay, true
}

// NextWithContext waits for the backoff duration or until context is canceled.
// Returns nil if wait completed, context error if canceled, or ErrMaxRetriesExceeded.
func (b *Backoff) NextWithContext(ctx context.Context) error {
	delay, ok := b.Next()
	if !ok {
		return ErrMaxRetriesExceeded
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Reset resets the attempt counter.
func (b *Backoff) Reset() {
	b.mu.Lock()
	b.attempt = 0
	b.mu.Unlock()
}

// Attempt returns the current attempt number.
func (b *Backoff) Attempt() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempt
}

func (b *Backoff) calculateDelay() time.Duration {
	// Calculate base delay with exponential backoff
	baseDelay := float64(b.cfg.InitialDelay) * math.Pow(b.cfg.Multiplier, float64(b.attempt))

	// Cap at max delay
	if baseDelay > float64(b.cfg.MaxDelay) {
		baseDelay = float64(b.cfg.MaxDelay)
	}

	// Add jitter
	if b.cfg.JitterFactor > 0 {
		jitter := baseDelay * b.cfg.JitterFactor
		// Random value in range [-jitter, +jitter]
		baseDelay += (b.rng.Float64()*2 - 1) * jitter
	}

	// Ensure non-negative
	if baseDelay < 0 {
		baseDelay = float64(b.cfg.InitialDelay)
	}

	return time.Duration(baseDelay)
}

// Do executes the function with retries according to the configuration.
func Do(ctx context.Context, cfg Config, fn func() error) error {
	backoff := NewBackoff(cfg)
	var lastErr error

	for {
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err

		// Check if error is retryable
		if cfg.RetryIf != nil && !cfg.RetryIf(err) {
			return err
		}

		// Wait for next retry
		waitErr := backoff.NextWithContext(ctx)
		if waitErr != nil {
			if errors.Is(waitErr, ErrMaxRetriesExceeded) {
				return lastErr
			}
			return waitErr
		}
	}
}

// DoWithResult executes the function with retries and returns the result.
func DoWithResult[T any](ctx context.Context, cfg Config, fn func() (T, error)) (T, error) {
	backoff := NewBackoff(cfg)
	var lastErr error
	var zero T

	for {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		lastErr = err

		// Check if error is retryable
		if cfg.RetryIf != nil && !cfg.RetryIf(err) {
			return zero, err
		}

		// Wait for next retry
		waitErr := backoff.NextWithContext(ctx)
		if waitErr != nil {
			if errors.Is(waitErr, ErrMaxRetriesExceeded) {
				return zero, lastErr
			}
			return zero, waitErr
		}
	}
}

// Jitter adds a random jitter to a duration.
// jitterFactor should be between 0 and 1 (e.g., 0.25 for ±25% jitter).
func Jitter(d time.Duration, jitterFactor float64) time.Duration {
	if jitterFactor <= 0 {
		return d
	}
	if jitterFactor > 1 {
		jitterFactor = 1
	}

	jitter := float64(d) * jitterFactor
	delta := (rand.Float64()*2 - 1) * jitter
	return time.Duration(float64(d) + delta)
}

// JitterRange returns a random duration between min and max.
func JitterRange(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	delta := max - min
	return min + time.Duration(rand.Int63n(int64(delta)))
}
