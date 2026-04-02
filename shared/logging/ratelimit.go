package logging

import (
	"sync"
	"time"
)

type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     map[string]time.Time
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &rateLimiter{
		interval: interval,
		last:     make(map[string]time.Time),
	}
}

func (r *rateLimiter) allow(key string) bool {
	if r == nil || r.interval <= 0 {
		return true
	}

	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if last, ok := r.last[key]; ok {
		if now.Sub(last) < r.interval {
			return false
		}
	}
	r.last[key] = now

	if len(r.last) > 1000 {
		cutoff := now.Add(-r.interval * 10)
		for k, t := range r.last {
			if t.Before(cutoff) {
				delete(r.last, k)
			}
		}
	}

	return true
}

func (l *Logger) RateLimitedLog(level Level, cat Category, key string, msg string, fields map[string]any) {
	if l.rateLimiter.allow(key) {
		l.log(level, cat, msg, fields)
	}
}

func (l *Logger) RateLimitedWarn(cat Category, key string, msg string, fields ...map[string]any) {
	if l.rateLimiter.allow(key) {
		l.Warn(cat, msg, fields...)
	}
}

func (l *Logger) RateLimitedError(cat Category, key string, msg string, fields ...map[string]any) {
	if l.rateLimiter.allow(key) {
		l.Error(cat, msg, fields...)
	}
}
