package logging

import (
	"sync"
	"time"
)

type DashboardEvent struct {
	TimeUnix  int64    `json:"time_unix"`
	Kind      string   `json:"kind"`
	Category  Category `json:"category"`
	Component string   `json:"component"`
	Route     string   `json:"route,omitempty"`
	RemoteIP  string   `json:"remote_ip,omitempty"`
	ConnID    string   `json:"conn_id,omitempty"`
	Message   string   `json:"message"`
	Detail    string   `json:"detail,omitempty"`
	Level     string   `json:"level"`
}

type DashboardHook struct {
	mu       sync.RWMutex
	events   []DashboardEvent
	maxSize  int
	minLevel Level

	rateMu   sync.Mutex
	rateKeys map[string]time.Time
	rateMin  time.Duration
}

func NewDashboardHook(maxSize int, minLevel Level) *DashboardHook {
	if maxSize <= 0 {
		maxSize = 500
	}
	return &DashboardHook{
		events:   make([]DashboardEvent, 0, maxSize),
		maxSize:  maxSize,
		minLevel: minLevel,
		rateKeys: make(map[string]time.Time),
		rateMin:  time.Second,
	}
}

func (d *DashboardHook) Hook() Hook {
	return func(entry Entry) {
		if entry.Level < d.minLevel {
			return
		}

		event := DashboardEvent{
			TimeUnix:  entry.Time.Unix(),
			Kind:      d.kindFromEntry(entry),
			Category:  entry.Category,
			Component: entry.Component,
			Message:   entry.Message,
			Level:     entry.LevelStr,
		}

		if route, ok := entry.Fields["route"].(string); ok {
			event.Route = route
		}
		if ip, ok := entry.Fields["remote_ip"].(string); ok {
			event.RemoteIP = ip
		}
		if id, ok := entry.Fields["conn_id"].(string); ok {
			event.ConnID = id
		}
		if detail, ok := entry.Fields["detail"].(string); ok {
			event.Detail = detail
		}
		if entry.ErrorStr != "" {
			if event.Detail == "" {
				event.Detail = entry.ErrorStr
			} else {
				event.Detail += ": " + entry.ErrorStr
			}
		}

		rateKey := string(event.Category) + "|" + event.Kind
		if !d.allowRated(rateKey) {
			return
		}

		d.addEvent(event)
	}
}

func (d *DashboardHook) kindFromEntry(entry Entry) string {
	if kind, ok := entry.Fields["kind"].(string); ok {
		return kind
	}

	prefix := ""
	switch entry.Level {
	case LevelError, LevelFatal:
		prefix = "error_"
	case LevelWarn:
		prefix = "warn_"
	default:
		prefix = "info_"
	}
	return prefix + string(entry.Category)
}

func (d *DashboardHook) allowRated(key string) bool {
	now := time.Now()
	d.rateMu.Lock()
	defer d.rateMu.Unlock()

	if last, ok := d.rateKeys[key]; ok {
		if now.Sub(last) < d.rateMin {
			return false
		}
	}
	d.rateKeys[key] = now
	return true
}

func (d *DashboardHook) addEvent(event DashboardEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.events = append(d.events, event)
	if len(d.events) > d.maxSize {
		copy(d.events, d.events[len(d.events)-d.maxSize:])
		d.events = d.events[:d.maxSize]
	}
}

func (d *DashboardHook) AddEvent(event DashboardEvent) {
	d.addEvent(event)
}

func (d *DashboardHook) Events() []DashboardEvent {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]DashboardEvent, len(d.events))
	copy(result, d.events)
	return result
}

func (d *DashboardHook) EventsSince(sinceUnix int64) []DashboardEvent {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []DashboardEvent
	for _, e := range d.events {
		if e.TimeUnix >= sinceUnix {
			result = append(result, e)
		}
	}
	return result
}

func (d *DashboardHook) EventsByCategory(cat Category) []DashboardEvent {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []DashboardEvent
	for _, e := range d.events {
		if e.Category == cat {
			result = append(result, e)
		}
	}
	return result
}

func (d *DashboardHook) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = d.events[:0]
}

type DashboardStats struct {
	TotalEvents   int            `json:"total_events"`
	EventsByLevel map[string]int `json:"events_by_level"`
	EventsByCat   map[string]int `json:"events_by_category"`
	RecentErrors  int            `json:"recent_errors"`
}

func (d *DashboardHook) Stats() DashboardStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := DashboardStats{
		TotalEvents:   len(d.events),
		EventsByLevel: make(map[string]int),
		EventsByCat:   make(map[string]int),
	}

	cutoff := time.Now().Add(-5 * time.Minute).Unix()
	for _, e := range d.events {
		stats.EventsByLevel[e.Level]++
		stats.EventsByCat[string(e.Category)]++
		if (e.Level == "ERROR" || e.Level == "FATAL") && e.TimeUnix >= cutoff {
			stats.RecentErrors++
		}
	}
	return stats
}
