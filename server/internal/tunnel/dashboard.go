package tunnel

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultDashboardBucketDur = 30 * time.Second
	maxRouteEvents            = 200
	dashboardHistory          = 7 * 24 * time.Hour // always keep 7 days
)

type DashboardPoint struct {
	StartUnix int64 `json:"t"`
	Bytes     int64 `json:"bytes"`
	Conns     int64 `json:"conns"`
}

type DashboardEvent struct {
	TimeUnix   int64  `json:"t"`
	Kind       string `json:"kind"`
	RemoteIP   string `json:"ip,omitempty"`
	ConnID     string `json:"id,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	DurationMS int64  `json:"durMs,omitempty"`
	Route      string `json:"route,omitempty"`
}

type DashboardRoute struct {
	ActiveClients int64            `json:"active"`
	Events        []DashboardEvent `json:"events"`
}

// UDPStats represents UDP traffic statistics for the dashboard.
type UDPStats struct {
	PacketsIn            int64   `json:"packetsIn"`
	PacketsOut           int64   `json:"packetsOut"`
	BytesIn              int64   `json:"bytesIn"`
	BytesOut             int64   `json:"bytesOut"`
	ActiveRoutes         int     `json:"activeRoutes"`
	LossPercent          float64 `json:"lossPercent"`
	TotalDrops           int64   `json:"totalDrops"`
	PublicQueueDrops     int64   `json:"publicQueueDrops"`
	AgentQueueDrops      int64   `json:"agentQueueDrops"`
	PublicWorkerDrops    int64   `json:"publicWorkerDrops"`
	AgentWorkerDrops     int64   `json:"agentWorkerDrops"`
	ResolveDrops         int64   `json:"resolveDrops"`
	DecodeDrops          int64   `json:"decodeDrops"`
	NoAgentDrops         int64   `json:"noAgentDrops"`
	RouteDisabledDrops   int64   `json:"routeDisabledDrops"`
	PayloadTooLargeDrops int64   `json:"payloadTooLargeDrops"`
	PublicWriteErrors    int64   `json:"publicWriteErrors"`
	AgentWriteErrors     int64   `json:"agentWriteErrors"`
	PublicQueueDepth     int64   `json:"publicQueueDepth"`
	PublicQueueCapacity  int64   `json:"publicQueueCapacity"`
	AgentQueueDepth      int64   `json:"agentQueueDepth"`
	AgentQueueCapacity   int64   `json:"agentQueueCapacity"`
}

type DashboardSnapshot struct {
	NowUnix        int64                     `json:"nowUnix"`
	BucketSec      int                       `json:"bucketSec"`
	AgentConnected bool                      `json:"agentConnected"`
	ActiveClients  int64                     `json:"activeClients"`
	BytesTotal     int64                     `json:"bytesTotal"`
	Series         []DashboardPoint          `json:"series"`
	Routes         map[string]DashboardRoute `json:"routes"`
	UDP            *UDPStats                 `json:"udp,omitempty"`
}

type bucket struct {
	startUnix int64
	bytes     int64
	conns     int64
}

type routeDash struct {
	active atomic.Int64
	mu     sync.Mutex
	events []DashboardEvent
}

type dashState struct {
	active     atomic.Int64
	bytesTotal atomic.Int64

	bucketDur   time.Duration
	bucketCount int

	mu      sync.Mutex
	buckets []bucket
	routes  map[string]*routeDash

	eventBatcher *dashEventBatcher
}

type dashEventBatcher struct {
	mu     sync.Mutex
	events map[string][]DashboardEvent
	ticker *time.Ticker
	done   chan struct{}
	dash   *dashState
}

func dashBucketCount(dur time.Duration) int {
	if dur <= 0 {
		dur = defaultDashboardBucketDur
	}
	return int(dashboardHistory / dur)
}

func newDashState() *dashState {
	return newDashStateWithInterval(defaultDashboardBucketDur)
}

func newDashStateWithInterval(dur time.Duration) *dashState {
	if dur <= 0 {
		dur = defaultDashboardBucketDur
	}
	count := dashBucketCount(dur)
	d := &dashState{
		bucketDur:   dur,
		bucketCount: count,
		buckets:     make([]bucket, count),
		routes:      map[string]*routeDash{},
	}
	d.eventBatcher = &dashEventBatcher{
		events: make(map[string][]DashboardEvent),
		ticker: time.NewTicker(50 * time.Millisecond),
		done:   make(chan struct{}),
		dash:   d,
	}
	go d.eventBatcher.start()
	return d
}

func (b *dashEventBatcher) start() {
	for {
		select {
		case <-b.done:
			b.ticker.Stop()
			return
		case <-b.ticker.C:
			b.flush()
		}
	}
}

func (b *dashEventBatcher) add(route string, ev DashboardEvent) {
	b.mu.Lock()
	b.events[route] = append(b.events[route], ev)
	b.mu.Unlock()
}

func (b *dashEventBatcher) flush() {
	b.mu.Lock()
	if len(b.events) == 0 {
		b.mu.Unlock()
		return
	}
	snapshot := b.events
	b.events = make(map[string][]DashboardEvent)
	b.mu.Unlock()

	// Process batches in parallel per route
	var wg sync.WaitGroup
	for route, events := range snapshot {
		wg.Add(1)
		go func(r string, evs []DashboardEvent) {
			defer wg.Done()
			rd := b.dash.route(r)
			rd.mu.Lock()
			rd.events = append(rd.events, evs...)
			if len(rd.events) > maxRouteEvents {
				rd.events = rd.events[len(rd.events)-maxRouteEvents:]
			}
			rd.mu.Unlock()
		}(route, events)
	}
	wg.Wait()
}

func (d *dashState) route(name string) *routeDash {
	name = strings.TrimSpace(name)
	d.mu.Lock()
	rd := d.routes[name]
	if rd == nil {
		rd = &routeDash{}
		d.routes[name] = rd
	}
	d.mu.Unlock()
	return rd
}

func (d *dashState) addBytes(at time.Time, n int64) {
	if n <= 0 {
		return
	}
	d.bytesTotal.Add(n)

	start := at.UTC().Truncate(d.bucketDur).Unix()
	idx := int((start / int64(d.bucketDur.Seconds())) % int64(d.bucketCount))
	if idx < 0 {
		idx = -idx
		idx = idx % d.bucketCount
	}

	d.mu.Lock()
	b := &d.buckets[idx]
	if b.startUnix != start {
		b.startUnix = start
		b.bytes = 0
		b.conns = 0
	}
	b.bytes += n
	d.mu.Unlock()
}

func (d *dashState) addConn(at time.Time) {
	start := at.UTC().Truncate(d.bucketDur).Unix()
	idx := int((start / int64(d.bucketDur.Seconds())) % int64(d.bucketCount))
	if idx < 0 {
		idx = -idx
		idx = idx % d.bucketCount
	}

	d.mu.Lock()
	b := &d.buckets[idx]
	if b.startUnix != start {
		b.startUnix = start
		b.bytes = 0
		b.conns = 0
	}
	b.conns++
	d.mu.Unlock()
}

func (d *dashState) addEvent(routeName string, ev DashboardEvent) {
	ev.Route = strings.TrimSpace(routeName)
	if d.eventBatcher != nil {
		d.eventBatcher.add(routeName, ev)
	} else {
		// Fallback if batcher not initialized
		rd := d.route(routeName)
		rd.mu.Lock()
		rd.events = append(rd.events, ev)
		if len(rd.events) > maxRouteEvents {
			rd.events = append([]DashboardEvent(nil), rd.events[len(rd.events)-maxRouteEvents:]...)
		}
		rd.mu.Unlock()
	}
}

func (d *dashState) incActive(routeName string) {
	d.active.Add(1)
	d.route(routeName).active.Add(1)
}

func (d *dashState) decActive(routeName string) {
	d.active.Add(-1)
	d.route(routeName).active.Add(-1)
}

func (d *dashState) snapshot(now time.Time, agentConnected bool) DashboardSnapshot {
	now = now.UTC()
	nowStart := now.Truncate(d.bucketDur).Unix()
	bucketSec := int64(d.bucketDur.Seconds())
	first := nowStart - int64(d.bucketCount-1)*bucketSec

	d.mu.Lock()
	type bucketData struct {
		bytes int64
		conns int64
	}
	bucketMap := make(map[int64]bucketData, d.bucketCount)
	for i := range d.buckets {
		b := d.buckets[i]
		if b.startUnix == 0 {
			continue
		}
		bucketMap[b.startUnix] = bucketData{bytes: b.bytes, conns: b.conns}
	}
	// Copy route pointers while holding lock.
	routes := make(map[string]*routeDash, len(d.routes))
	for k, v := range d.routes {
		routes[k] = v
	}
	d.mu.Unlock()

	series := make([]DashboardPoint, 0, d.bucketCount)
	for i := 0; i < d.bucketCount; i++ {
		t := first + int64(i)*bucketSec
		bd := bucketMap[t]
		series = append(series, DashboardPoint{StartUnix: t, Bytes: bd.bytes, Conns: bd.conns})
	}

	// Stable route ordering for snapshot assembly.
	names := make([]string, 0, len(routes))
	for name := range routes {
		if strings.TrimSpace(name) == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	outRoutes := make(map[string]DashboardRoute, len(names))
	for _, name := range names {
		rd := routes[name]
		if rd == nil {
			continue
		}
		rd.mu.Lock()
		evCopy := append([]DashboardEvent(nil), rd.events...)
		rd.mu.Unlock()
		outRoutes[name] = DashboardRoute{ActiveClients: rd.active.Load(), Events: evCopy}
	}

	return DashboardSnapshot{
		NowUnix:        now.Unix(),
		BucketSec:      int(d.bucketDur.Seconds()),
		AgentConnected: agentConnected,
		ActiveClients:  d.active.Load(),
		BytesTotal:     d.bytesTotal.Load(),
		Series:         series,
		Routes:         outRoutes,
	}
}
