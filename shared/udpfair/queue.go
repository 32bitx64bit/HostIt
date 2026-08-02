package udpfair

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrClosed = errors.New("UDP fair queue closed")
	ErrFull   = errors.New("UDP fair queue full")
)

// Limits bounds queued memory and metadata. Global limits include system and
// route traffic. Per-route limits apply independently to each route, while the
// system limits keep tunnel control traffic's own footprint deliberately small.
type Limits struct {
	GlobalMaxBytes     int
	GlobalMaxPackets   int
	PerRouteMaxBytes   int
	PerRouteMaxPackets int
	SystemMaxBytes     int
	SystemMaxPackets   int
	RouteMaxAge        time.Duration
	SystemMaxAge       time.Duration
}

// DefaultLimits returns conservative application-queue bounds. Kernel socket
// buffers are separate and must also be bounded by the caller.
func DefaultLimits() Limits {
	return Limits{
		GlobalMaxBytes:     2 * 1024 * 1024,
		GlobalMaxPackets:   2048,
		PerRouteMaxBytes:   256 * 1024,
		PerRouteMaxPackets: 256,
		SystemMaxBytes:     128 * 1024,
		SystemMaxPackets:   64,
		RouteMaxAge:        100 * time.Millisecond,
		SystemMaxAge:       2 * time.Second,
	}
}

// Item is returned by Dequeue. The queue owns a private copy of Payload. An
// Item must not be copied after dequeue. Call Release exactly once when
// processing is complete; all references to Payload become invalid then.
type Item[T any] struct {
	Route      string
	System     bool
	Payload    []byte
	Meta       T
	EnqueuedAt time.Time

	buffer   *payloadBuffer
	released bool
}

// Release returns the payload buffer to its capacity-bucketed pool. It is
// idempotent on this Item instance. Copying an Item and releasing both copies
// is invalid because it could return the same backing array twice.
func (i *Item[T]) Release() {
	if i.released {
		return
	}
	i.released = true
	buffer := i.buffer
	i.buffer = nil
	i.Payload = nil
	if buffer == nil {
		return
	}
	if buffer.pool == nil {
		buffer.data = nil
		return
	}
	buffer.data = buffer.data[:0]
	buffer.pool.Put(buffer)
}

type DropStats struct {
	Overflow uint64
	Expired  uint64
	Closed   uint64
}

// SubqueueStats describes either the system queue or one route queue.
type SubqueueStats struct {
	QueuedPackets int
	QueuedBytes   int
	Enqueued      uint64
	Dequeued      uint64
	Dropped       DropStats
}

// Stats is a consistent queue snapshot. Routes contains only currently
// backlogged routes; global counters remain cumulative after a route drains.
type Stats struct {
	QueuedPackets int
	QueuedBytes   int
	ActiveRoutes  int
	Enqueued      uint64
	Dequeued      uint64
	Dropped       DropStats
	System        SubqueueStats
	Routes        map[string]SubqueueStats
}

type queueOptions struct {
	now func() time.Time
}

// Option customizes a Queue.
type Option func(*queueOptions)

// WithClock installs the clock used by Enqueue, TryDequeue, Dequeue, and
// Stats. TryDequeueAt remains available for callers with an explicit time.
func WithClock(now func() time.Time) Option {
	return func(o *queueOptions) {
		if now != nil {
			o.now = now
		}
	}
}

const (
	minPooledPayloadBytes = 64
	maxPooledPayloadBytes = 64 * 1024
	payloadPoolBuckets    = 11 // 64, 128, ... 65536
	maxCachedRouteQueues  = 64
)

type payloadBuffer struct {
	data []byte
	pool *sync.Pool
}

type queuedItem[T any] struct {
	item Item[T]
	cost int
}

// fifo is a compact ring. Popped slots are zeroed so payload and metadata
// references are released promptly.
type fifo[T any] struct {
	items []queuedItem[T]
	head  int
	len   int
	bytes int
}

func (f *fifo[T]) push(v queuedItem[T]) {
	if f.len == cap(f.items) {
		newCap := cap(f.items) * 2
		if newCap < 8 {
			newCap = 8
		}
		next := make([]queuedItem[T], newCap)
		for i := 0; i < f.len; i++ {
			next[i] = f.items[(f.head+i)%cap(f.items)]
		}
		f.items = next
		f.head = 0
	}
	idx := (f.head + f.len) % cap(f.items)
	f.items[idx] = v
	f.len++
	f.bytes += v.cost
}

func (f *fifo[T]) front() *queuedItem[T] {
	if f.len == 0 {
		return nil
	}
	return &f.items[f.head]
}

func (f *fifo[T]) pop() (queuedItem[T], bool) {
	if f.len == 0 {
		return queuedItem[T]{}, false
	}
	v := f.items[f.head]
	var zero queuedItem[T]
	f.items[f.head] = zero
	f.head = (f.head + 1) % cap(f.items)
	f.len--
	f.bytes -= v.cost
	if f.len == 0 {
		f.head = 0
	}
	return v, true
}

type routeQueue[T any] struct {
	name  string
	fifo  fifo[T]
	stats SubqueueStats
}

// Queue is a concurrency-safe fair queue for one consumer. System traffic has
// strict priority. Route traffic is served one packet per active route in
// round-robin order, so a busy route cannot starve a sparse route and an idle
// route does not reserve bandwidth. Producers may call enqueue concurrently.
// Only one goroutine should call Dequeue/TryDequeue.
type Queue[T any] struct {
	mu sync.Mutex

	limits Limits
	system fifo[T]
	routes map[string]*routeQueue[T]
	active []*routeQueue[T]
	cursor int

	now     func() time.Time
	wake    chan struct{} // capacity one; reused for the queue's lifetime
	closed  bool
	buffers [payloadPoolBuckets]sync.Pool

	stats       Stats
	systemStats SubqueueStats
	idleRoutes  []*routeQueue[T]
}

// NewQueue validates limits and creates an empty queue.
func NewQueue[T any](limits Limits, options ...Option) (*Queue[T], error) {
	if err := validateLimits(limits); err != nil {
		return nil, err
	}
	opts := queueOptions{now: time.Now}
	for _, option := range options {
		if option != nil {
			option(&opts)
		}
	}
	return &Queue[T]{
		limits: limits,
		now:    opts.now,
		wake:   make(chan struct{}, 1),
		routes: make(map[string]*routeQueue[T]),
	}, nil
}

func validateLimits(l Limits) error {
	positive := []struct {
		name  string
		value int
	}{
		{"global byte", l.GlobalMaxBytes},
		{"global packet", l.GlobalMaxPackets},
		{"per-route byte", l.PerRouteMaxBytes},
		{"per-route packet", l.PerRouteMaxPackets},
		{"system byte", l.SystemMaxBytes},
		{"system packet", l.SystemMaxPackets},
	}
	for _, field := range positive {
		if field.value <= 0 {
			return fmt.Errorf("%s limit must be positive", field.name)
		}
	}
	if l.PerRouteMaxBytes > l.GlobalMaxBytes {
		return errors.New("per-route byte limit exceeds global byte limit")
	}
	if l.PerRouteMaxPackets > l.GlobalMaxPackets {
		return errors.New("per-route packet limit exceeds global packet limit")
	}
	if l.SystemMaxBytes > l.GlobalMaxBytes {
		return errors.New("system byte limit exceeds global byte limit")
	}
	if l.SystemMaxPackets > l.GlobalMaxPackets {
		return errors.New("system packet limit exceeds global packet limit")
	}
	if l.RouteMaxAge <= 0 {
		return errors.New("route maximum age must be positive")
	}
	if l.SystemMaxAge <= 0 {
		return errors.New("system maximum age must be positive")
	}
	return nil
}

// EnqueueRoute copies payload and admits it to route's FIFO. Per-route
// overflow evicts that route's oldest packets, favoring fresh UDP data. At a
// global bound, packets are evicted from the fattest route; this prevents one
// continuously backlogged route from crowding sparse routes out of the queue.
// System traffic is never evicted to admit route traffic.
func (q *Queue[T]) EnqueueRoute(route string, payload []byte, meta T) error {
	now := q.now()
	cost := len(payload)
	if cost == 0 {
		cost = 1
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		q.recordDropLocked(nil, dropClosed)
		return ErrClosed
	}
	q.expireLocked(now)
	if cost > q.limits.PerRouteMaxBytes || cost > q.limits.GlobalMaxBytes {
		q.recordDropLocked(nil, dropOverflow)
		return ErrFull
	}

	routeQ := q.routes[route]
	if routeQ == nil {
		routeQ = q.acquireRouteLocked(route)
	}
	stats := &routeQ.stats
	for routeQ.fifo.bytes+cost > q.limits.PerRouteMaxBytes || routeQ.fifo.len+1 > q.limits.PerRouteMaxPackets {
		q.dropRouteOldestLocked(routeQ, dropOverflow, true)
	}

	for q.exceedsGlobalLocked(cost, 1) {
		victim := q.fattestRouteLocked(q.stats.QueuedBytes+cost > q.limits.GlobalMaxBytes)
		if victim == nil {
			q.recordDropLocked(stats, dropOverflow)
			if routeQ.fifo.len == 0 {
				q.retireRouteLocked(routeQ)
			}
			return ErrFull
		}
		q.dropRouteOldestLocked(victim, dropOverflow, victim == routeQ)
	}

	owned, buffer := q.ownPayloadLocked(payload)
	wasEmpty := routeQ.fifo.len == 0
	routeQ.fifo.push(queuedItem[T]{
		item: Item[T]{Route: route, Payload: owned, Meta: meta, EnqueuedAt: now, buffer: buffer},
		cost: cost,
	})
	if wasEmpty && !q.routeActiveLocked(routeQ) {
		q.active = append(q.active, routeQ)
	}
	q.recordEnqueueLocked(stats, cost)
	q.notifyLocked()
	return nil
}

// EnqueueSystem copies payload into the strict-priority system queue. A fresh
// system packet first evicts stale/old system packets at its own bound, then
// evicts route traffic if needed at the global bound. This keeps registration
// and other tunnel control messages independent of data-route congestion.
func (q *Queue[T]) EnqueueSystem(payload []byte, meta T) error {
	now := q.now()
	cost := len(payload)
	if cost == 0 {
		cost = 1
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		q.recordDropLocked(&q.systemStats, dropClosed)
		return ErrClosed
	}
	q.expireLocked(now)
	if cost > q.limits.SystemMaxBytes || cost > q.limits.GlobalMaxBytes {
		q.recordDropLocked(&q.systemStats, dropOverflow)
		return ErrFull
	}
	for q.system.bytes+cost > q.limits.SystemMaxBytes || q.system.len+1 > q.limits.SystemMaxPackets {
		q.dropSystemOldestLocked(dropOverflow)
	}
	for q.exceedsGlobalLocked(cost, 1) {
		victim := q.fattestRouteLocked(q.stats.QueuedBytes+cost > q.limits.GlobalMaxBytes)
		if victim != nil {
			q.dropRouteOldestLocked(victim, dropOverflow, false)
			continue
		}
		if q.system.len == 0 {
			q.recordDropLocked(&q.systemStats, dropOverflow)
			return ErrFull
		}
		q.dropSystemOldestLocked(dropOverflow)
	}

	owned, buffer := q.ownPayloadLocked(payload)
	q.system.push(queuedItem[T]{
		item: Item[T]{System: true, Payload: owned, Meta: meta, EnqueuedAt: now, buffer: buffer},
		cost: cost,
	})
	q.recordEnqueueLocked(&q.systemStats, cost)
	q.notifyLocked()
	return nil
}

// TryDequeue returns the next non-expired item without waiting.
func (q *Queue[T]) TryDequeue() (Item[T], bool) {
	return q.TryDequeueAt(q.now())
}

// TryDequeueAt is TryDequeue with an explicit time, useful for deterministic
// expiry tests.
func (q *Queue[T]) TryDequeueAt(now time.Time) (Item[T], bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dequeueLocked(now)
}

// Dequeue waits for the next non-expired item. Context cancellation affects
// only this wait; it does not close or drain the shared queue.
func (q *Queue[T]) Dequeue(ctx context.Context) (Item[T], error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		q.mu.Lock()
		item, ok := q.dequeueLocked(q.now())
		closed := q.closed
		q.mu.Unlock()
		if ok {
			return item, nil
		}
		if closed {
			return Item[T]{}, ErrClosed
		}

		select {
		case <-ctx.Done():
			return Item[T]{}, ctx.Err()
		case <-q.wake:
		}
	}
}

// Close rejects future enqueues, discards queued items, returns their payload
// buffers, and wakes all current waiters. It is idempotent.
func (q *Queue[T]) Close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	for q.system.len != 0 {
		q.dropSystemOldestLocked(dropClosed)
	}
	for len(q.active) != 0 {
		routeQ := q.active[0]
		for routeQ.fifo.len != 0 {
			q.dropRouteOldestLocked(routeQ, dropClosed, true)
		}
		q.retireRouteLocked(routeQ)
	}
	close(q.wake)
	q.mu.Unlock()
}

// Stats returns a consistent snapshot. It also accounts for packets that have
// expired since the previous queue operation.
func (q *Queue[T]) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.expireLocked(q.now())
	out := q.stats
	out.ActiveRoutes = len(q.active)
	out.System = q.systemStats
	out.Routes = make(map[string]SubqueueStats, len(q.routes))
	for route, routeQ := range q.routes {
		out.Routes[route] = routeQ.stats
	}
	return out
}

func (q *Queue[T]) dequeueLocked(now time.Time) (Item[T], bool) {
	q.expireLocked(now)
	if item, ok := q.system.pop(); ok {
		q.recordDequeueLocked(&q.systemStats, item.cost)
		return item.item, true
	}
	if len(q.active) == 0 {
		return Item[T]{}, false
	}
	if q.cursor >= len(q.active) {
		q.cursor = 0
	}
	idx := q.cursor
	routeQ := q.active[idx]
	item, _ := routeQ.fifo.pop()
	q.recordDequeueLocked(&routeQ.stats, item.cost)
	if routeQ.fifo.len == 0 {
		q.retireRouteAtLocked(idx)
	} else {
		q.cursor = (idx + 1) % len(q.active)
	}
	return item.item, true
}

func (q *Queue[T]) expireLocked(now time.Time) {
	for {
		front := q.system.front()
		if front == nil || now.Sub(front.item.EnqueuedAt) < q.limits.SystemMaxAge {
			break
		}
		q.dropSystemOldestLocked(dropExpired)
	}
	for idx := 0; idx < len(q.active); {
		routeQ := q.active[idx]
		for {
			front := routeQ.fifo.front()
			if front == nil || now.Sub(front.item.EnqueuedAt) < q.limits.RouteMaxAge {
				break
			}
			q.dropRouteOldestLocked(routeQ, dropExpired, true)
		}
		if routeQ.fifo.len == 0 {
			q.retireRouteAtLocked(idx)
			continue
		}
		idx++
	}
}

func (q *Queue[T]) exceedsGlobalLocked(addBytes, addPackets int) bool {
	return q.stats.QueuedBytes+addBytes > q.limits.GlobalMaxBytes ||
		q.stats.QueuedPackets+addPackets > q.limits.GlobalMaxPackets
}

// fattestRouteLocked chooses by queued bytes when the byte bound is exceeded,
// otherwise by packet count. Ties retain active-list order for determinism.
func (q *Queue[T]) fattestRouteLocked(byBytes bool) *routeQueue[T] {
	var largest *routeQueue[T]
	for _, routeQ := range q.active {
		if routeQ.fifo.len == 0 {
			continue
		}
		if largest == nil ||
			(byBytes && routeQ.fifo.bytes > largest.fifo.bytes) ||
			(!byBytes && routeQ.fifo.len > largest.fifo.len) {
			largest = routeQ
		}
	}
	return largest
}

type dropReason uint8

const (
	dropOverflow dropReason = iota
	dropExpired
	dropClosed
)

func (q *Queue[T]) dropSystemOldestLocked(reason dropReason) bool {
	item, ok := q.system.pop()
	if !ok {
		return false
	}
	q.recordRemovalLocked(&q.systemStats, item.cost)
	q.recordDropLocked(&q.systemStats, reason)
	item.item.Release()
	return true
}

func (q *Queue[T]) dropRouteOldestLocked(routeQ *routeQueue[T], reason dropReason, retainEmpty bool) bool {
	item, ok := routeQ.fifo.pop()
	if !ok {
		return false
	}
	q.recordRemovalLocked(&routeQ.stats, item.cost)
	q.recordDropLocked(&routeQ.stats, reason)
	item.item.Release()
	if routeQ.fifo.len == 0 && !retainEmpty {
		q.retireRouteLocked(routeQ)
	}
	return true
}

func (q *Queue[T]) recordEnqueueLocked(stats *SubqueueStats, bytes int) {
	q.stats.QueuedPackets++
	q.stats.QueuedBytes += bytes
	q.stats.Enqueued++
	stats.QueuedPackets++
	stats.QueuedBytes += bytes
	stats.Enqueued++
}

func (q *Queue[T]) recordDequeueLocked(stats *SubqueueStats, bytes int) {
	q.recordRemovalLocked(stats, bytes)
	q.stats.Dequeued++
	stats.Dequeued++
}

func (q *Queue[T]) recordRemovalLocked(stats *SubqueueStats, bytes int) {
	q.stats.QueuedPackets--
	q.stats.QueuedBytes -= bytes
	stats.QueuedPackets--
	stats.QueuedBytes -= bytes
}

func (q *Queue[T]) recordDropLocked(stats *SubqueueStats, reason dropReason) {
	switch reason {
	case dropOverflow:
		q.stats.Dropped.Overflow++
		if stats != nil {
			stats.Dropped.Overflow++
		}
	case dropExpired:
		q.stats.Dropped.Expired++
		if stats != nil {
			stats.Dropped.Expired++
		}
	case dropClosed:
		q.stats.Dropped.Closed++
		if stats != nil {
			stats.Dropped.Closed++
		}
	}
}

func (q *Queue[T]) routeActiveLocked(routeQ *routeQueue[T]) bool {
	for _, candidate := range q.active {
		if candidate == routeQ {
			return true
		}
	}
	return false
}

func (q *Queue[T]) acquireRouteLocked(route string) *routeQueue[T] {
	var routeQ *routeQueue[T]
	if n := len(q.idleRoutes); n != 0 {
		routeQ = q.idleRoutes[n-1]
		q.idleRoutes[n-1] = nil
		q.idleRoutes = q.idleRoutes[:n-1]
	} else {
		routeQ = &routeQueue[T]{}
	}
	routeQ.name = route
	routeQ.stats = SubqueueStats{}
	routeQ.fifo.head = 0
	routeQ.fifo.len = 0
	routeQ.fifo.bytes = 0
	q.routes[route] = routeQ
	return routeQ
}

func (q *Queue[T]) retireRouteLocked(routeQ *routeQueue[T]) {
	for idx, candidate := range q.active {
		if candidate == routeQ {
			q.retireRouteAtLocked(idx)
			return
		}
	}
	if current := q.routes[routeQ.name]; current == routeQ {
		delete(q.routes, routeQ.name)
		q.cacheRouteLocked(routeQ)
	}
}

func (q *Queue[T]) retireRouteAtLocked(idx int) {
	routeQ := q.active[idx]
	q.removeActiveAtLocked(idx)
	delete(q.routes, routeQ.name)
	q.cacheRouteLocked(routeQ)
}

func (q *Queue[T]) cacheRouteLocked(routeQ *routeQueue[T]) {
	routeQ.name = ""
	routeQ.stats = SubqueueStats{}
	if len(q.idleRoutes) < maxCachedRouteQueues {
		q.idleRoutes = append(q.idleRoutes, routeQ)
	}
}

func (q *Queue[T]) removeActiveAtLocked(idx int) {
	copy(q.active[idx:], q.active[idx+1:])
	q.active[len(q.active)-1] = nil
	q.active = q.active[:len(q.active)-1]
	if len(q.active) == 0 {
		q.cursor = 0
		return
	}
	if idx < q.cursor {
		q.cursor--
	}
	if q.cursor >= len(q.active) {
		q.cursor = 0
	}
}

func (q *Queue[T]) ownPayloadLocked(payload []byte) ([]byte, *payloadBuffer) {
	if len(payload) == 0 {
		return nil, nil
	}
	if len(payload) > maxPooledPayloadBytes {
		buffer := &payloadBuffer{data: append([]byte(nil), payload...)}
		return buffer.data, buffer
	}
	bucket, capacity := payloadPoolBucket(len(payload))
	pool := &q.buffers[bucket]
	buffer, _ := pool.Get().(*payloadBuffer)
	if buffer == nil {
		buffer = &payloadBuffer{data: make([]byte, capacity), pool: pool}
	}
	buffer.data = buffer.data[:len(payload)]
	copy(buffer.data, payload)
	return buffer.data, buffer
}

func payloadPoolBucket(size int) (bucket, capacity int) {
	capacity = minPooledPayloadBytes
	for capacity < size {
		capacity <<= 1
		bucket++
	}
	return bucket, capacity
}

func (q *Queue[T]) notifyLocked() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}
