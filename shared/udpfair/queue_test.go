package udpfair

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func testLimits() Limits {
	return Limits{
		GlobalMaxBytes:     1024,
		GlobalMaxPackets:   64,
		PerRouteMaxBytes:   1024,
		PerRouteMaxPackets: 64,
		SystemMaxBytes:     1024,
		SystemMaxPackets:   64,
		RouteMaxAge:        time.Minute,
		SystemMaxAge:       time.Minute,
	}
}

func mustQueue[T any](t *testing.T, limits Limits, options ...Option) *Queue[T] {
	t.Helper()
	q, err := NewQueue[T](limits, options...)
	if err != nil {
		t.Fatalf("NewQueue: %v", err)
	}
	return q
}

func drainMeta[T comparable](t *testing.T, q *Queue[T]) []T {
	t.Helper()
	var out []T
	for {
		item, ok := q.TryDequeue()
		if !ok {
			return out
		}
		out = append(out, item.Meta)
		item.Release()
	}
}

func TestQueueSystemPriorityAndRouteFairness(t *testing.T) {
	q := mustQueue[string](t, testLimits())
	for _, in := range []struct {
		route string
		meta  string
	}{
		{"video", "video-1"},
		{"video", "video-2"},
		{"video", "video-3"},
		{"input", "input-1"},
	} {
		if err := q.EnqueueRoute(in.route, []byte(in.meta), in.meta); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.EnqueueSystem([]byte("register"), "register"); err != nil {
		t.Fatal(err)
	}

	want := []string{"register", "video-1", "input-1", "video-2", "video-3"}
	got := drainMeta(t, q)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("dequeue order = %v, want %v", got, want)
	}
}

func TestQueueFIFOWithinEachRoute(t *testing.T) {
	q := mustQueue[string](t, testLimits())
	for _, in := range []struct {
		route string
		meta  string
	}{
		{"a", "a1"},
		{"b", "b1"},
		{"a", "a2"},
		{"b", "b2"},
		{"a", "a3"},
	} {
		if err := q.EnqueueRoute(in.route, []byte(in.meta), in.meta); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"a1", "b1", "a2", "b2", "a3"}
	if got := drainMeta(t, q); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("dequeue order = %v, want %v", got, want)
	}
}

func TestQueueIsWorkConserving(t *testing.T) {
	q := mustQueue[int](t, testLimits())
	for i := range 20 {
		if err := q.EnqueueRoute("only-route", []byte{byte(i)}, i); err != nil {
			t.Fatal(err)
		}
	}
	for want := range 20 {
		item, ok := q.TryDequeue()
		if !ok || item.Meta != want {
			t.Fatalf("dequeue = (%v, %t), want %d", item.Meta, ok, want)
		}
		item.Release()
	}
	if _, ok := q.TryDequeue(); ok {
		t.Fatal("queue retained an unexpected item")
	}
}

func TestQueueOwnsAndReleasesPayload(t *testing.T) {
	q := mustQueue[struct{}](t, testLimits())
	source := []byte("original")
	if err := q.EnqueueRoute("route", source, struct{}{}); err != nil {
		t.Fatal(err)
	}
	copy(source, "mutated!")
	item, ok := q.TryDequeue()
	if !ok {
		t.Fatal("queued item missing")
	}
	if string(item.Payload) != "original" {
		t.Fatalf("payload = %q, want owned original", item.Payload)
	}

	item.Release()
	item.Release()
	if item.Payload != nil {
		t.Fatal("Release did not clear payload references")
	}

	if err := q.EnqueueRoute("route", []byte("next"), struct{}{}); err != nil {
		t.Fatal(err)
	}
	next, ok := q.TryDequeue()
	if !ok || string(next.Payload) != "next" {
		t.Fatalf("next payload = %q, queued=%t", next.Payload, ok)
	}
	next.Release()
}

func TestQueuePerRouteByteBoundEvictsOldest(t *testing.T) {
	limits := testLimits()
	limits.PerRouteMaxBytes = 6
	q := mustQueue[string](t, limits)
	if err := q.EnqueueRoute("video", []byte("aaaa"), "old"); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueRoute("video", []byte("bbbb"), "new"); err != nil {
		t.Fatal(err)
	}
	stats := q.Stats()
	if stats.QueuedBytes != 4 || stats.Routes["video"].QueuedBytes != 4 || stats.Dropped.Overflow != 1 {
		t.Fatalf("stats after per-route byte eviction = %+v", stats)
	}
	if got := drainMeta(t, q); fmt.Sprint(got) != "[new]" {
		t.Fatalf("remaining packets = %v, want [new]", got)
	}
}

func TestQueuePerRoutePacketBoundContainsZeroLengthFlood(t *testing.T) {
	limits := testLimits()
	limits.PerRouteMaxPackets = 3
	q := mustQueue[int](t, limits)
	for i := range 100 {
		if err := q.EnqueueRoute("empty", nil, i); err != nil {
			t.Fatal(err)
		}
	}
	stats := q.Stats()
	if stats.QueuedPackets != 3 || stats.QueuedBytes != 3 {
		t.Fatalf("zero-length queue size = %d packets/%d charged bytes, want 3/3", stats.QueuedPackets, stats.QueuedBytes)
	}
	if stats.Dropped.Overflow != 97 {
		t.Fatalf("overflow drops = %d, want 97", stats.Dropped.Overflow)
	}
	want := []int{97, 98, 99}
	if got := drainMeta(t, q); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("remaining packets = %v, want %v", got, want)
	}
}

func TestQueueGlobalByteBoundDropsFromFattestRoute(t *testing.T) {
	limits := testLimits()
	limits.GlobalMaxBytes = 10
	limits.PerRouteMaxBytes = 10
	limits.SystemMaxBytes = 10
	q := mustQueue[string](t, limits)
	if err := q.EnqueueRoute("a", []byte("123456"), "a"); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueRoute("b", []byte("1234"), "b"); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueRoute("c", []byte("12"), "c"); err != nil {
		t.Fatal(err)
	}
	stats := q.Stats()
	if stats.QueuedBytes != 6 || stats.Dropped.Overflow != 1 || len(stats.Routes) != 2 {
		t.Fatalf("stats after global byte eviction = %+v", stats)
	}
	want := []string{"b", "c"}
	if got := drainMeta(t, q); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("remaining packets = %v, want %v", got, want)
	}
}

func TestQueueGlobalPacketBoundDropsFromFattestRoute(t *testing.T) {
	limits := testLimits()
	limits.GlobalMaxPackets = 3
	limits.PerRouteMaxPackets = 3
	limits.SystemMaxPackets = 3
	q := mustQueue[string](t, limits)
	for _, in := range []struct {
		route string
		meta  string
	}{
		{"a", "a1"},
		{"a", "a2"},
		{"b", "b1"},
		{"c", "c1"},
	} {
		if err := q.EnqueueRoute(in.route, nil, in.meta); err != nil {
			t.Fatal(err)
		}
	}
	stats := q.Stats()
	if stats.QueuedPackets != 3 || stats.Dropped.Overflow != 1 || stats.Routes["a"].Dropped.Overflow != 1 {
		t.Fatalf("stats after global packet eviction = %+v", stats)
	}
	want := []string{"a2", "b1", "c1"}
	if got := drainMeta(t, q); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("remaining packets = %v, want %v", got, want)
	}
}

func TestSystemAdmissionEvictsRoutesButRoutesCannotEvictSystem(t *testing.T) {
	limits := testLimits()
	limits.GlobalMaxPackets = 2
	limits.PerRouteMaxPackets = 2
	limits.SystemMaxPackets = 2
	q := mustQueue[string](t, limits)
	if err := q.EnqueueRoute("video", nil, "data-1"); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueRoute("video", nil, "data-2"); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueSystem(nil, "system-1"); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueSystem(nil, "system-2"); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueRoute("input", nil, "data-3"); !errors.Is(err, ErrFull) {
		t.Fatalf("route enqueue error = %v, want ErrFull", err)
	}
	if err := q.EnqueueSystem(nil, "system-3"); err != nil {
		t.Fatal(err)
	}
	want := []string{"system-2", "system-3"}
	if got := drainMeta(t, q); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("remaining packets = %v, want %v", got, want)
	}
	stats := q.Stats()
	if stats.Dropped.Overflow != 4 || stats.System.Dropped.Overflow != 1 || len(stats.Routes) != 0 {
		t.Fatalf("overflow attribution = %+v", stats)
	}
}

func TestQueueRejectsIndividuallyOversizedPackets(t *testing.T) {
	limits := testLimits()
	limits.PerRouteMaxBytes = 3
	limits.SystemMaxBytes = 2
	q := mustQueue[struct{}](t, limits)
	if err := q.EnqueueRoute("route", []byte("four"), struct{}{}); !errors.Is(err, ErrFull) {
		t.Fatalf("route error = %v, want ErrFull", err)
	}
	if err := q.EnqueueSystem([]byte("abc"), struct{}{}); !errors.Is(err, ErrFull) {
		t.Fatalf("system error = %v, want ErrFull", err)
	}
	stats := q.Stats()
	if stats.QueuedPackets != 0 || stats.Dropped.Overflow != 2 {
		t.Fatalf("oversize stats = %+v", stats)
	}
}

func TestQueueExpiryWithFakeClock(t *testing.T) {
	clock := &fakeClock{now: time.Unix(100, 0)}
	limits := testLimits()
	limits.RouteMaxAge = 10 * time.Millisecond
	limits.SystemMaxAge = 20 * time.Millisecond
	q := mustQueue[string](t, limits, WithClock(clock.Now))
	if err := q.EnqueueRoute("route", []byte("route"), "route"); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueSystem([]byte("system"), "system"); err != nil {
		t.Fatal(err)
	}
	clock.Advance(10 * time.Millisecond)
	item, ok := q.TryDequeue()
	if !ok || item.Meta != "system" {
		t.Fatalf("dequeue after route expiry = (%q, %t), want system", item.Meta, ok)
	}
	item.Release()
	if err := q.EnqueueSystem([]byte("expire-me"), "expire-me"); err != nil {
		t.Fatal(err)
	}
	clock.Advance(20 * time.Millisecond)
	if _, ok := q.TryDequeue(); ok {
		t.Fatal("expired system item was dequeued")
	}
	stats := q.Stats()
	if stats.Dropped.Expired != 2 || len(stats.Routes) != 0 || stats.System.Dropped.Expired != 1 {
		t.Fatalf("expiry stats = %+v", stats)
	}
}

func TestQueueCancellationCloseAndWake(t *testing.T) {
	q := mustQueue[string](t, testLimits())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.Dequeue(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Dequeue canceled error = %v", err)
	}

	const waiters = 4
	started := make(chan struct{}, waiters)
	results := make(chan error, waiters)
	for range waiters {
		go func() {
			started <- struct{}{}
			_, err := q.Dequeue(context.Background())
			results <- err
		}()
	}
	for range waiters {
		<-started
	}
	q.Close()
	q.Close()
	for range waiters {
		if err := <-results; !errors.Is(err, ErrClosed) {
			t.Fatalf("waiter error = %v, want ErrClosed", err)
		}
	}
	if err := q.EnqueueRoute("late", nil, "late"); !errors.Is(err, ErrClosed) {
		t.Fatalf("route enqueue after close = %v", err)
	}
	if err := q.EnqueueSystem(nil, "late"); !errors.Is(err, ErrClosed) {
		t.Fatalf("system enqueue after close = %v", err)
	}
}

func TestEnqueueWakesBlockedConsumer(t *testing.T) {
	q := mustQueue[string](t, testLimits())
	result := make(chan string, 1)
	go func() {
		item, err := q.Dequeue(context.Background())
		if err != nil {
			result <- "error: " + err.Error()
			return
		}
		result <- item.Meta
		item.Release()
	}()
	if err := q.EnqueueRoute("input", []byte("wake"), "woke"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got != "woke" {
			t.Fatalf("consumer result = %q, want woke", got)
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue did not wake blocked consumer")
	}
}

func TestQueueCloseReleasesAndAccountsForQueuedItems(t *testing.T) {
	q := mustQueue[string](t, testLimits())
	if err := q.EnqueueRoute("route", []byte("data"), "data"); err != nil {
		t.Fatal(err)
	}
	if err := q.EnqueueSystem([]byte("system"), "system"); err != nil {
		t.Fatal(err)
	}
	q.Close()
	stats := q.Stats()
	if stats.QueuedPackets != 0 || stats.QueuedBytes != 0 || stats.Dropped.Closed != 2 {
		t.Fatalf("close stats = %+v", stats)
	}
	if _, err := q.Dequeue(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Dequeue after close = %v, want ErrClosed", err)
	}
}

func TestQueueDoesNotReplaceWakeChannelOnEnqueue(t *testing.T) {
	q := mustQueue[int](t, testLimits())
	wake := q.wake
	for i := range 10 {
		if err := q.EnqueueRoute("route", nil, i); err != nil {
			t.Fatal(err)
		}
	}
	if q.wake != wake {
		t.Fatal("enqueue replaced the queue wake channel")
	}
}

func TestQueueStatsSnapshotIsIndependent(t *testing.T) {
	q := mustQueue[int](t, testLimits())
	if err := q.EnqueueRoute("route", []byte("x"), 1); err != nil {
		t.Fatal(err)
	}
	first := q.Stats()
	first.Routes["route"] = SubqueueStats{}
	second := q.Stats()
	if second.Routes["route"].QueuedPackets != 1 {
		t.Fatalf("mutating snapshot changed queue stats: %+v", second)
	}
	item, _ := q.TryDequeue()
	item.Release()
}

func TestQueueReclaimsRouteStateAfterNameChurn(t *testing.T) {
	q := mustQueue[int](t, testLimits())
	for i := range 1000 {
		route := fmt.Sprintf("dynamic-%d", i)
		if err := q.EnqueueRoute(route, nil, i); err != nil {
			t.Fatal(err)
		}
		item, ok := q.TryDequeue()
		if !ok || item.Meta != i {
			t.Fatalf("dequeue %d = (%d, %t)", i, item.Meta, ok)
		}
		item.Release()
	}
	stats := q.Stats()
	if len(q.routes) != 0 || len(q.active) != 0 || len(stats.Routes) != 0 || stats.ActiveRoutes != 0 {
		t.Fatalf("route state leaked: routes=%d active=%d stats=%+v", len(q.routes), len(q.active), stats)
	}
	if len(q.idleRoutes) > maxCachedRouteQueues {
		t.Fatalf("idle route cache grew to %d, max %d", len(q.idleRoutes), maxCachedRouteQueues)
	}
}

func TestPayloadPoolsAreCapacityBucketed(t *testing.T) {
	q := mustQueue[struct{}](t, testLimits())
	if err := q.EnqueueRoute("route", make([]byte, 65), struct{}{}); err != nil {
		t.Fatal(err)
	}
	large, _ := q.TryDequeue()
	if cap(large.Payload) != 128 {
		t.Fatalf("65-byte payload capacity = %d, want 128", cap(large.Payload))
	}
	large.Release()

	if err := q.EnqueueRoute("route", []byte{1}, struct{}{}); err != nil {
		t.Fatal(err)
	}
	small, _ := q.TryDequeue()
	if cap(small.Payload) != 64 {
		t.Fatalf("1-byte payload capacity = %d, want 64", cap(small.Payload))
	}
	small.Release()
}

func TestQueueConcurrentProducersAndConsumer(t *testing.T) {
	const producers = 8
	const perProducer = 200
	const total = producers * perProducer

	limits := DefaultLimits()
	limits.GlobalMaxBytes = 4 * 1024 * 1024
	limits.GlobalMaxPackets = total
	limits.PerRouteMaxBytes = 512 * 1024
	limits.PerRouteMaxPackets = perProducer
	q := mustQueue[string](t, limits)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	seen := make(map[string]struct{}, total)
	var seenMu sync.Mutex
	consumerDone := make(chan error, 1)
	go func() {
		for range total {
			item, err := q.Dequeue(ctx)
			if err != nil {
				consumerDone <- err
				return
			}
			seenMu.Lock()
			if _, duplicate := seen[item.Meta]; duplicate {
				seenMu.Unlock()
				item.Release()
				consumerDone <- fmt.Errorf("duplicate item %q", item.Meta)
				return
			}
			seen[item.Meta] = struct{}{}
			seenMu.Unlock()
			item.Release()
		}
		consumerDone <- nil
	}()

	var producersWG sync.WaitGroup
	for producer := range producers {
		producersWG.Add(1)
		go func(producer int) {
			defer producersWG.Done()
			route := fmt.Sprintf("route-%d", producer)
			for i := range perProducer {
				id := fmt.Sprintf("%d/%d", producer, i)
				if err := q.EnqueueRoute(route, []byte(id), id); err != nil {
					t.Errorf("EnqueueRoute(%s): %v", id, err)
					return
				}
			}
		}(producer)
	}
	producersWG.Wait()
	if err := <-consumerDone; err != nil {
		t.Fatal(err)
	}
	if len(seen) != total {
		t.Fatalf("received %d unique items, want %d", len(seen), total)
	}
	stats := q.Stats()
	if stats.Enqueued != total || stats.Dequeued != total || stats.QueuedPackets != 0 {
		t.Fatalf("final stats = %+v", stats)
	}
}

func TestNewQueueRejectsInvalidLimits(t *testing.T) {
	valid := testLimits()
	tests := []struct {
		name   string
		mutate func(*Limits)
	}{
		{"zero global bytes", func(l *Limits) { l.GlobalMaxBytes = 0 }},
		{"zero global packets", func(l *Limits) { l.GlobalMaxPackets = 0 }},
		{"zero route bytes", func(l *Limits) { l.PerRouteMaxBytes = 0 }},
		{"zero route packets", func(l *Limits) { l.PerRouteMaxPackets = 0 }},
		{"zero system bytes", func(l *Limits) { l.SystemMaxBytes = 0 }},
		{"zero system packets", func(l *Limits) { l.SystemMaxPackets = 0 }},
		{"route bytes exceed global", func(l *Limits) { l.PerRouteMaxBytes = l.GlobalMaxBytes + 1 }},
		{"route packets exceed global", func(l *Limits) { l.PerRouteMaxPackets = l.GlobalMaxPackets + 1 }},
		{"system bytes exceed global", func(l *Limits) { l.SystemMaxBytes = l.GlobalMaxBytes + 1 }},
		{"system packets exceed global", func(l *Limits) { l.SystemMaxPackets = l.GlobalMaxPackets + 1 }},
		{"zero route age", func(l *Limits) { l.RouteMaxAge = 0 }},
		{"zero system age", func(l *Limits) { l.SystemMaxAge = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := valid
			test.mutate(&limits)
			if _, err := NewQueue[struct{}](limits); err == nil {
				t.Fatal("NewQueue accepted invalid limits")
			}
		})
	}
}

func BenchmarkQueueEnqueueDequeue(b *testing.B) {
	limits := DefaultLimits()
	q, err := NewQueue[struct{}](limits)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1200)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if err := q.EnqueueRoute("video", payload, struct{}{}); err != nil {
			b.Fatal(err)
		}
		item, ok := q.TryDequeue()
		if !ok {
			b.Fatal("queued item missing")
		}
		item.Release()
	}
}
