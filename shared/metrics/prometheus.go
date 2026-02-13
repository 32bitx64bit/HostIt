package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricType represents the type of a metric.
type MetricType int

const (
	Counter MetricType = iota
	Gauge
	Histogram
)

// Metric represents a single metric with its metadata.
type Metric struct {
	Name        string
	Type        MetricType
	Help        string
	Labels      []string
	LabelValues []string
	Value       float64
}

// Collector collects and stores metrics.
type Collector struct {
	mu       sync.RWMutex
	counters map[string]*counterMetric
	gauges   map[string]*gaugeMetric
}

type counterMetric struct {
	value     atomic.Uint64
	help      string
	labels    []string
	labelKeys map[string]int // label name -> index in labels slice
}

type gaugeMetric struct {
	value     atomic.Uint64 // Stores IEEE 754 binary representation
	help      string
	labels    []string
	labelKeys map[string]int
}

// NewCollector creates a new metrics collector.
func NewCollector() *Collector {
	return &Collector{
		counters: make(map[string]*counterMetric),
		gauges:   make(map[string]*gaugeMetric),
	}
}

// RegisterCounter registers a new counter metric.
func (c *Collector) RegisterCounter(name, help string, labels ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.counters[name]; !exists {
		labelKeys := make(map[string]int)
		for i, l := range labels {
			labelKeys[l] = i
		}
		c.counters[name] = &counterMetric{
			help:      help,
			labels:    labels,
			labelKeys: labelKeys,
		}
	}
}

// RegisterGauge registers a new gauge metric.
func (c *Collector) RegisterGauge(name, help string, labels ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.gauges[name]; !exists {
		labelKeys := make(map[string]int)
		for i, l := range labels {
			labelKeys[l] = i
		}
		c.gauges[name] = &gaugeMetric{
			help:      help,
			labels:    labels,
			labelKeys: labelKeys,
		}
	}
}

// IncCounter increments a counter by 1.
func (c *Collector) IncCounter(name string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if m, ok := c.counters[name]; ok {
		m.value.Add(1)
	}
}

// AddCounter adds a value to a counter.
func (c *Collector) AddCounter(name string, delta uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if m, ok := c.counters[name]; ok {
		m.value.Add(delta)
	}
}

// SetGauge sets a gauge to a specific value.
func (c *Collector) SetGauge(name string, value float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if m, ok := c.gauges[name]; ok {
		m.value.Store(math.Float64bits(value))
	}
}

// AddGauge adds a value to a gauge.
func (c *Collector) AddGauge(name string, delta float64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if m, ok := c.gauges[name]; ok {
		for {
			old := m.value.Load()
			oldFloat := math.Float64frombits(old)
			newVal := oldFloat + delta
			if m.value.CompareAndSwap(old, math.Float64bits(newVal)) {
				break
			}
		}
	}
}

// GetCounter returns the current value of a counter.
func (c *Collector) GetCounter(name string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if m, ok := c.counters[name]; ok {
		return m.value.Load()
	}
	return 0
}

// GetGauge returns the current value of a gauge.
func (c *Collector) GetGauge(name string) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if m, ok := c.gauges[name]; ok {
		return math.Float64frombits(m.value.Load())
	}
	return 0
}

// ExportPrometheus exports all metrics in Prometheus text format.
func (c *Collector) ExportPrometheus() string {
	var sb strings.Builder

	// Export counters
	c.mu.RLock()
	for name, m := range c.counters {
		sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, m.help))
		sb.WriteString(fmt.Sprintf("# TYPE %s counter\n", name))
		sb.WriteString(fmt.Sprintf("%s %d\n", name, m.value.Load()))
	}

	// Export gauges
	for name, m := range c.gauges {
		sb.WriteString(fmt.Sprintf("# HELP %s %s\n", name, m.help))
		sb.WriteString(fmt.Sprintf("# TYPE %s gauge\n", name))
		sb.WriteString(fmt.Sprintf("%s %g\n", name, math.Float64frombits(m.value.Load())))
	}
	c.mu.RUnlock()

	return sb.String()
}

// ExportJSON exports all metrics as JSON.
func (c *Collector) ExportJSON() ([]byte, error) {
	data := make(map[string]interface{})

	c.mu.RLock()
	for name, m := range c.counters {
		data[name] = m.value.Load()
	}
	for name, m := range c.gauges {
		data[name] = math.Float64frombits(m.value.Load())
	}
	c.mu.RUnlock()

	return json.Marshal(data)
}

// Handler returns an http.Handler for the /metrics endpoint.
func (c *Collector) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		format := r.URL.Query().Get("format")
		if format == "json" {
			data, err := c.ExportJSON()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
			return
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Write([]byte(c.ExportPrometheus()))
	}
}

// Global collector instance
var globalCollector = NewCollector()

// DefaultCollector returns the global collector.
func DefaultCollector() *Collector {
	return globalCollector
}

// Standard metric names for UDP tunnel
const (
	// Packet metrics
	MetricPacketsSent     = "udp_packets_sent_total"
	MetricPacketsReceived = "udp_packets_received_total"
	MetricPacketsDropped  = "udp_packets_dropped_total"
	MetricPacketsLost     = "udp_packets_lost_total"
	MetricBytesSent       = "udp_bytes_sent_total"
	MetricBytesReceived   = "udp_bytes_received_total"

	// Queue metrics
	MetricQueueDepth    = "udp_queue_depth"
	MetricQueueCapacity = "udp_queue_capacity"
	MetricQueueLatency  = "udp_queue_latency_seconds"
	MetricQueueDrops    = "udp_queue_drops_total"

	// Session metrics
	MetricActiveSessions  = "udp_active_sessions"
	MetricSessionDuration = "udp_session_duration_seconds"

	// Congestion metrics
	MetricCongestionMode    = "udp_congestion_mode"
	MetricCongestionBackoff = "udp_congestion_backoff_seconds"

	// Connection metrics
	MetricTCPConnections = "tcp_connections_active"
	MetricTCPBytes       = "tcp_bytes_total"
	MetricTCPPairLatency = "tcp_pair_latency_seconds"

	// System metrics
	MetricGoroutines  = "go_goroutines"
	MetricMemoryAlloc = "go_memory_alloc_bytes"
	MetricMemorySys   = "go_memory_sys_bytes"
	MetricGCRuns      = "go_gc_runs_total"
)

// RegisterStandardMetrics registers all standard metrics.
func RegisterStandardMetrics() {
	c := globalCollector

	// Packet metrics
	c.RegisterCounter(MetricPacketsSent, "Total number of UDP packets sent")
	c.RegisterCounter(MetricPacketsReceived, "Total number of UDP packets received")
	c.RegisterCounter(MetricPacketsDropped, "Total number of UDP packets dropped")
	c.RegisterCounter(MetricPacketsLost, "Total number of UDP packets detected as lost")
	c.RegisterCounter(MetricBytesSent, "Total number of UDP bytes sent")
	c.RegisterCounter(MetricBytesReceived, "Total number of UDP bytes received")

	// Queue metrics
	c.RegisterGauge(MetricQueueDepth, "Current depth of the UDP write queue")
	c.RegisterGauge(MetricQueueCapacity, "Capacity of the UDP write queue")
	c.RegisterGauge(MetricQueueLatency, "Average latency in the UDP write queue")
	c.RegisterCounter(MetricQueueDrops, "Total number of UDP queue drops")

	// Session metrics
	c.RegisterGauge(MetricActiveSessions, "Number of active UDP sessions")
	c.RegisterGauge(MetricSessionDuration, "Average UDP session duration")

	// Congestion metrics
	c.RegisterGauge(MetricCongestionMode, "Whether UDP is in congestion mode (0 or 1)")
	c.RegisterGauge(MetricCongestionBackoff, "Current congestion backoff duration")

	// Connection metrics
	c.RegisterGauge(MetricTCPConnections, "Number of active TCP connections")
	c.RegisterCounter(MetricTCPBytes, "Total TCP bytes transferred")
	c.RegisterGauge(MetricTCPPairLatency, "TCP pairing latency")

	// System metrics
	c.RegisterGauge(MetricGoroutines, "Number of goroutines")
	c.RegisterGauge(MetricMemoryAlloc, "Bytes of allocated heap objects")
	c.RegisterGauge(MetricMemorySys, "Total bytes of memory obtained from the OS")
	c.RegisterCounter(MetricGCRuns, "Total number of GC runs")
}

// UpdateSystemMetrics updates Go runtime metrics.
func UpdateSystemMetrics() {
	c := globalCollector

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	c.SetGauge(MetricGoroutines, float64(runtime.NumGoroutine()))
	c.SetGauge(MetricMemoryAlloc, float64(m.Alloc))
	c.SetGauge(MetricMemorySys, float64(m.Sys))
	c.AddCounter(MetricGCRuns, uint64(m.NumGC))
}

// StartMetricsUpdater starts a goroutine that periodically updates system metrics.
func StartMetricsUpdater(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				UpdateSystemMetrics()
			}
		}
	}()
}
