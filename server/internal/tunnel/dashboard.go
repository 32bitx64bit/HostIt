package tunnel

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dashboardBucketDur   = 5 * time.Minute
	dashboardBucketCount = 7 * 24 * 12 // 7 days @ 5m
	maxRouteEvents       = 200
)

type DashboardPoint struct {
	StartUnix int64 `json:"t"`
	Bytes     int64 `json:"bytes"`
}

type DashboardEvent struct {
	TimeUnix    int64  `json:"t"`
	Kind        string `json:"kind"`
	RemoteIP    string `json:"ip,omitempty"`
	ConnID      string `json:"id,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
	DurationMS  int64  `json:"durMs,omitempty"`
	Route       string `json:"route,omitempty"`
}

type DashboardRoute struct {
	ActiveClients int64            `json:"active"`
	Events        []DashboardEvent `json:"events"`
}

type DashboardSnapshot struct {
	NowUnix       int64                      `json:"nowUnix"`
	AgentConnected bool                      `json:"agentConnected"`
	ActiveClients int64                      `json:"activeClients"`
	BytesTotal    int64                      `json:"bytesTotal"`
	Series        []DashboardPoint           `json:"series"`
	Routes        map[string]DashboardRoute  `json:"routes"`
}

type bucket struct {
	startUnix int64
	bytes     int64
}

type routeDash struct {
	active atomic.Int64
	mu     sync.Mutex
	events []DashboardEvent
}

type dashState struct {
	active     atomic.Int64
	bytesTotal atomic.Int64

	mu      sync.Mutex
	buckets []bucket
	routes  map[string]*routeDash
}

func newDashState() *dashState {
	return &dashState{
		buckets: make([]bucket, dashboardBucketCount),
		routes:  map[string]*routeDash{},
	}
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

	start := at.UTC().Truncate(dashboardBucketDur).Unix()
	idx := int((start / int64(dashboardBucketDur.Seconds())) % dashboardBucketCount)
	if idx < 0 {
		idx = -idx
		idx = idx % dashboardBucketCount
	}

	d.mu.Lock()
	b := &d.buckets[idx]
	if b.startUnix != start {
		b.startUnix = start
		b.bytes = 0
	}
	b.bytes += n
	d.mu.Unlock()
}

func (d *dashState) addEvent(routeName string, ev DashboardEvent) {
	rd := d.route(routeName)
	ev.Route = strings.TrimSpace(routeName)

	rd.mu.Lock()
	rd.events = append(rd.events, ev)
	if len(rd.events) > maxRouteEvents {
		rd.events = append([]DashboardEvent(nil), rd.events[len(rd.events)-maxRouteEvents:]...)
	}
	rd.mu.Unlock()
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
	nowStart := now.Truncate(dashboardBucketDur).Unix()
	bucketSec := int64(dashboardBucketDur.Seconds())
	first := nowStart - int64(dashboardBucketCount-1)*bucketSec

	d.mu.Lock()
	bucketMap := make(map[int64]int64, dashboardBucketCount)
	for i := range d.buckets {
		b := d.buckets[i]
		if b.startUnix == 0 {
			continue
		}
		bucketMap[b.startUnix] = b.bytes
	}
	// Copy route pointers while holding lock.
	routes := make(map[string]*routeDash, len(d.routes))
	for k, v := range d.routes {
		routes[k] = v
	}
	d.mu.Unlock()

	series := make([]DashboardPoint, 0, dashboardBucketCount)
	for i := 0; i < dashboardBucketCount; i++ {
		t := first + int64(i)*bucketSec
		series = append(series, DashboardPoint{StartUnix: t, Bytes: bucketMap[t]})
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
		AgentConnected: agentConnected,
		ActiveClients:  d.active.Load(),
		BytesTotal:     d.bytesTotal.Load(),
		Series:         series,
		Routes:         outRoutes,
	}
}
