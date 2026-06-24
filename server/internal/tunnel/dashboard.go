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

type DashboardSnapshot struct {
	NowUnix        int64                     `json:"nowUnix"`
	BucketSec      int                       `json:"bucketSec"`
	AgentConnected bool                      `json:"agentConnected"`
	Agents         []AgentStatus             `json:"agents,omitempty"`
	ActiveClients  int64                     `json:"activeClients"`
	BytesTotal     int64                     `json:"bytesTotal"`
	Series         []DashboardPoint          `json:"series"`
	Routes         map[string]DashboardRoute `json:"routes"`
	Runtime        *DashboardRuntime         `json:"runtime,omitempty"`
}

type AgentStatus struct {
	ID                 string `json:"id"`
	Connected          bool   `json:"connected"`
	Registered         bool   `json:"registered"`
	RemoteAddr         string `json:"remoteAddr,omitempty"`
	ConnectedSinceUnix int64  `json:"connectedSinceUnix,omitempty"`
	FirstSeenUnix      int64  `json:"firstSeenUnix,omitempty"`
	UDPRegistered      bool   `json:"udpRegistered"`
	RouteCount         int    `json:"routeCount"`
	DomainEnabled      bool   `json:"domainEnabled"`
	EmailAgent         bool   `json:"emailAgent"`
}

type DashboardRuntime struct {
	PendingTCP              int   `json:"pendingTcp"`
	AgentSessions           int   `json:"agentSessions"`
	ManagedProxyRoutes      int   `json:"managedProxyRoutes"`
	ManagedDomains          int   `json:"managedDomains"`
	RouteCacheEntries       int   `json:"routeCacheEntries"`
	LastAgentConnectUnix    int64 `json:"lastAgentConnectUnix"`
	LastAgentDisconnectUnix int64 `json:"lastAgentDisconnectUnix"`
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
	return d
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
	rd := d.route(routeName)
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
