package udputil

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryPressureLevel represents the current memory pressure level.
type MemoryPressureLevel int

const (
	// MemoryPressureNone indicates normal memory conditions.
	MemoryPressureNone MemoryPressureLevel = iota
	// MemoryPressureLow indicates memory usage is elevated.
	MemoryPressureLow
	// MemoryPressureMedium indicates memory usage is high.
	MemoryPressureMedium
	// MemoryPressureHigh indicates memory usage is critical.
	MemoryPressureHigh
)

// String returns a string representation of the memory pressure level.
func (l MemoryPressureLevel) String() string {
	switch l {
	case MemoryPressureNone:
		return "none"
	case MemoryPressureLow:
		return "low"
	case MemoryPressureMedium:
		return "medium"
	case MemoryPressureHigh:
		return "high"
	default:
		return "unknown"
	}
}

// MemoryMonitor monitors memory usage and triggers callbacks when pressure changes.
type MemoryMonitor struct {
	mu sync.RWMutex

	// Configuration
	lowThreshold    uint64 // bytes
	mediumThreshold uint64 // bytes
	highThreshold   uint64 // bytes
	checkInterval   time.Duration

	// State
	currentLevel atomic.Int32
	lastCheck    time.Time

	// Callbacks
	onPressureChange func(old, newLevel MemoryPressureLevel)
	onHighPressure   func()

	// Stats
	totalChecks  atomic.Uint64
	levelChanges atomic.Uint64
	gcTriggered  atomic.Uint64
}

// MemoryMonitorConfig configures the memory monitor.
type MemoryMonitorConfig struct {
	LowThreshold     uint64
	MediumThreshold  uint64
	HighThreshold    uint64
	CheckInterval    time.Duration
	OnPressureChange func(old, newLevel MemoryPressureLevel)
	OnHighPressure   func()
}

// DefaultMemoryMonitorConfig returns sensible defaults.
func DefaultMemoryMonitorConfig() MemoryMonitorConfig {
	return MemoryMonitorConfig{
		LowThreshold:    100 * 1024 * 1024,  // 100 MB
		MediumThreshold: 500 * 1024 * 1024,  // 500 MB
		HighThreshold:   1024 * 1024 * 1024, // 1 GB
		CheckInterval:   time.Second,
	}
}

// NewMemoryMonitor creates a new memory monitor.
func NewMemoryMonitor(config MemoryMonitorConfig) *MemoryMonitor {
	return &MemoryMonitor{
		lowThreshold:     config.LowThreshold,
		mediumThreshold:  config.MediumThreshold,
		highThreshold:    config.HighThreshold,
		checkInterval:    config.CheckInterval,
		onPressureChange: config.OnPressureChange,
		onHighPressure:   config.OnHighPressure,
	}
}

// Check checks the current memory usage and updates the pressure level.
func (m *MemoryMonitor) Check() MemoryPressureLevel {
	m.totalChecks.Add(1)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Use Alloc (heap objects) as the primary metric
	alloc := memStats.Alloc

	var newLevel MemoryPressureLevel
	switch {
	case alloc >= m.highThreshold:
		newLevel = MemoryPressureHigh
	case alloc >= m.mediumThreshold:
		newLevel = MemoryPressureMedium
	case alloc >= m.lowThreshold:
		newLevel = MemoryPressureLow
	default:
		newLevel = MemoryPressureNone
	}

	oldLevel := MemoryPressureLevel(m.currentLevel.Load())
	if newLevel != oldLevel {
		m.currentLevel.Store(int32(newLevel))
		m.levelChanges.Add(1)

		m.mu.RLock()
		callback := m.onPressureChange
		m.mu.RUnlock()

		if callback != nil {
			callback(oldLevel, newLevel)
		}

		if newLevel == MemoryPressureHigh {
			m.mu.RLock()
			highCallback := m.onHighPressure
			m.mu.RUnlock()

			if highCallback != nil {
				highCallback()
			}
		}
	}

	return newLevel
}

// CurrentLevel returns the current memory pressure level.
func (m *MemoryMonitor) CurrentLevel() MemoryPressureLevel {
	return MemoryPressureLevel(m.currentLevel.Load())
}

// Start starts a background goroutine that periodically checks memory.
func (m *MemoryMonitor) Start(ctx interface{ Done() <-chan struct{} }) {
	go func() {
		ticker := time.NewTicker(m.checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.Check()
			}
		}
	}()
}

// Stats returns memory monitor statistics.
func (m *MemoryMonitor) Stats() MemoryMonitorStats {
	return MemoryMonitorStats{
		CurrentLevel: m.CurrentLevel(),
		TotalChecks:  m.totalChecks.Load(),
		LevelChanges: m.levelChanges.Load(),
		GCTriggered:  m.gcTriggered.Load(),
	}
}

// MemoryMonitorStats contains memory monitor statistics.
type MemoryMonitorStats struct {
	CurrentLevel MemoryPressureLevel `json:"current_level"`
	TotalChecks  uint64              `json:"total_checks"`
	LevelChanges uint64              `json:"level_changes"`
	GCTriggered  uint64              `json:"gc_triggered"`
}

// TriggerGC triggers a garbage collection and records it.
func (m *MemoryMonitor) TriggerGC() {
	m.gcTriggered.Add(1)
	runtime.GC()
}

// PressureAwarePool is a sync.Pool that shrinks under memory pressure.
type PressureAwarePool struct {
	pool        sync.Pool
	monitor     *MemoryMonitor
	maxItems    int32
	currentSize atomic.Int32
	shrinkRatio float64
}

// PressureAwarePoolConfig configures a pressure-aware pool.
type PressureAwarePoolConfig struct {
	New         func() any
	MaxItems    int32
	ShrinkRatio float64 // Ratio of items to drop under pressure (0.0 to 1.0)
	Monitor     *MemoryMonitor
}

// NewPressureAwarePool creates a new pressure-aware pool.
func NewPressureAwarePool(config PressureAwarePoolConfig) *PressureAwarePool {
	if config.ShrinkRatio <= 0 || config.ShrinkRatio > 1 {
		config.ShrinkRatio = 0.5
	}

	p := &PressureAwarePool{
		maxItems:    config.MaxItems,
		shrinkRatio: config.ShrinkRatio,
		monitor:     config.Monitor,
	}
	p.pool.New = config.New

	// Register for pressure changes
	if config.Monitor != nil {
		config.Monitor.mu.Lock()
		oldCallback := config.Monitor.onPressureChange
		config.Monitor.onPressureChange = func(old, newLevel MemoryPressureLevel) {
			if oldCallback != nil {
				oldCallback(old, newLevel)
			}
			if newLevel >= MemoryPressureMedium {
				p.Shrink()
			}
		}
		config.Monitor.mu.Unlock()
	}

	return p
}

// Get gets an item from the pool.
func (p *PressureAwarePool) Get() any {
	p.currentSize.Add(-1)
	return p.pool.Get()
}

// Put puts an item back into the pool.
func (p *PressureAwarePool) Put(x any) {
	// Check if we should accept the item
	currentSize := p.currentSize.Load()
	if p.maxItems > 0 && currentSize >= p.maxItems {
		// Pool is full, drop the item
		return
	}

	// Check memory pressure
	if p.monitor != nil && p.monitor.CurrentLevel() >= MemoryPressureHigh {
		// Under high pressure, don't add to pool
		return
	}

	p.currentSize.Add(1)
	p.pool.Put(x)
}

// Shrink reduces the pool size under memory pressure.
func (p *PressureAwarePool) Shrink() {
	currentSize := p.currentSize.Load()
	if currentSize <= 0 {
		return
	}

	// Calculate how many items to drop
	toDrop := int32(float64(currentSize) * p.shrinkRatio)
	if toDrop < 1 {
		toDrop = 1
	}

	// Remove items from pool
	for i := int32(0); i < toDrop; i++ {
		item := p.pool.Get()
		if item == nil {
			break
		}
		p.currentSize.Add(-1)
		// Let GC collect the item
	}
}

// Size returns the current pool size.
func (p *PressureAwarePool) Size() int32 {
	return p.currentSize.Load()
}

// BufferPool manages a pool of byte buffers with memory pressure awareness.
type BufferPool struct {
	pools   map[int]*PressureAwarePool // Size-indexed pools
	mu      sync.RWMutex
	monitor *MemoryMonitor
	sizes   []int // Available buffer sizes
}

// BufferPoolConfig configures a buffer pool.
type BufferPoolConfig struct {
	Sizes      []int // Buffer sizes to support (e.g., 4KB, 16KB, 64KB)
	MaxPerSize int32 // Max buffers per size
	Monitor    *MemoryMonitor
}

// DefaultBufferPoolConfig returns sensible defaults.
func DefaultBufferPoolConfig() BufferPoolConfig {
	return BufferPoolConfig{
		Sizes:      []int{4 * 1024, 16 * 1024, 64 * 1024},
		MaxPerSize: 100,
	}
}

// NewBufferPool creates a new buffer pool.
func NewBufferPool(config BufferPoolConfig) *BufferPool {
	if len(config.Sizes) == 0 {
		config.Sizes = DefaultBufferPoolConfig().Sizes
	}

	bp := &BufferPool{
		pools:   make(map[int]*PressureAwarePool),
		monitor: config.Monitor,
		sizes:   config.Sizes,
	}

	for _, size := range config.Sizes {
		size := size // Capture for closure
		bp.pools[size] = NewPressureAwarePool(PressureAwarePoolConfig{
			New: func() any {
				buf := make([]byte, size)
				return &buf
			},
			MaxItems:    config.MaxPerSize,
			ShrinkRatio: 0.5,
			Monitor:     config.Monitor,
		})
	}

	return bp
}

// Get gets a buffer of at least the requested size.
func (bp *BufferPool) Get(size int) *[]byte {
	// Find the smallest pool that can satisfy the request
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	for _, poolSize := range bp.sizes {
		if poolSize >= size {
			if pool, ok := bp.pools[poolSize]; ok {
				buf := pool.Get()
				if buf != nil {
					return buf.(*[]byte)
				}
			}
		}
	}

	// No suitable pool found, allocate directly
	buf := make([]byte, size)
	return &buf
}

// Put returns a buffer to the pool.
func (bp *BufferPool) Put(buf *[]byte) {
	if buf == nil {
		return
	}

	size := cap(*buf)

	bp.mu.RLock()
	defer bp.mu.RUnlock()

	// Find the matching pool
	for _, poolSize := range bp.sizes {
		if poolSize == size {
			if pool, ok := bp.pools[poolSize]; ok {
				pool.Put(buf)
				return
			}
		}
	}

	// No matching pool, let GC collect
}

// ShrinkAll shrinks all pools in the buffer pool.
func (bp *BufferPool) ShrinkAll() {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	for _, pool := range bp.pools {
		pool.Shrink()
	}
}

// Stats returns statistics for all pools.
func (bp *BufferPool) Stats() map[int]int32 {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	stats := make(map[int]int32)
	for size, pool := range bp.pools {
		stats[size] = pool.Size()
	}
	return stats
}
