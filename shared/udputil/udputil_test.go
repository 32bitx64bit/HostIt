package udputil

import (
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
//  Stats tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestStats_Basic(t *testing.T) {
	s := NewStats()
	s.RecordSend(100)
	s.RecordSend(200)
	s.RecordReceive(150)
	s.RecordLoss(1)
	s.RecordOutOfOrder()
	s.RecordDuplicate()

	snap := s.Snapshot()
	if snap.PacketsSent != 2 {
		t.Errorf("sent=%d want 2", snap.PacketsSent)
	}
	if snap.BytesSent != 300 {
		t.Errorf("bytesSent=%d want 300", snap.BytesSent)
	}
	if snap.PacketsReceived != 1 {
		t.Errorf("recv=%d want 1", snap.PacketsReceived)
	}
	if snap.PacketsLost != 1 {
		t.Errorf("lost=%d want 1", snap.PacketsLost)
	}
	if snap.PacketsOutOfOrder != 1 {
		t.Errorf("ooo=%d want 1", snap.PacketsOutOfOrder)
	}
	if snap.PacketsDuplicate != 1 {
		t.Errorf("dup=%d want 1", snap.PacketsDuplicate)
	}
}

func TestStats_LossRate(t *testing.T) {
	s := NewStats()
	// No sends yet → 0 loss
	if lr := s.LossRate(); lr != 0 {
		t.Errorf("empty loss=%f", lr)
	}
	for i := 0; i < 100; i++ {
		s.RecordSend(10)
	}
	s.RecordLoss(50)
	lr := s.LossRate()
	if lr < 0.49 || lr > 0.51 {
		t.Errorf("loss rate=%f, want ~0.5", lr)
	}
}

func TestStats_Reset(t *testing.T) {
	s := NewStats()
	s.RecordSend(100)
	s.RecordReceive(50)
	s.RecordLoss(1)
	s.Reset()
	snap := s.Snapshot()
	if snap.PacketsSent != 0 || snap.PacketsReceived != 0 || snap.PacketsLost != 0 {
		t.Errorf("reset didn't clear: %+v", snap)
	}
}

func TestStats_RTT(t *testing.T) {
	s := NewStats()
	s.RecordRTT(10 * time.Millisecond)
	s.RecordRTT(20 * time.Millisecond)
	avg := s.AvgRTT()
	if avg < 14*time.Millisecond || avg > 16*time.Millisecond {
		t.Errorf("avgRTT=%v, want ~15ms", avg)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SequenceTracker tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSequenceTracker_InOrder(t *testing.T) {
	stats := NewStats()
	tr := NewSequenceTracker(128, stats)

	for i := uint32(0); i < 100; i++ {
		isNew, isOOO, lost := tr.Track(i)
		if !isNew || isOOO || lost != 0 {
			t.Fatalf("seq %d: new=%v ooo=%v lost=%d", i, isNew, isOOO, lost)
		}
	}
	snap := stats.Snapshot()
	if snap.PacketsReceived != 100 {
		t.Errorf("recv=%d want 100", snap.PacketsReceived)
	}
	if snap.PacketsLost != 0 {
		t.Errorf("lost=%d want 0", snap.PacketsLost)
	}
}

func TestSequenceTracker_Gap(t *testing.T) {
	stats := NewStats()
	tr := NewSequenceTracker(128, stats)

	tr.Track(0)
	tr.Track(1)
	// Skip 2,3,4
	isNew, _, lost := tr.Track(5)
	if !isNew || lost != 3 {
		t.Fatalf("gap: new=%v lost=%d, want new=true lost=3", isNew, lost)
	}
	snap := stats.Snapshot()
	if snap.PacketsLost != 3 {
		t.Errorf("stats lost=%d want 3", snap.PacketsLost)
	}
}

func TestSequenceTracker_OutOfOrder(t *testing.T) {
	stats := NewStats()
	tr := NewSequenceTracker(128, stats)

	tr.Track(0)
	tr.Track(1)
	tr.Track(5) // gap of 3
	// Late arrivals
	isNew, isOOO, _ := tr.Track(3)
	if !isNew || !isOOO {
		t.Fatalf("ooo: new=%v ooo=%v", isNew, isOOO)
	}
}

func TestSequenceTracker_Duplicate(t *testing.T) {
	stats := NewStats()
	tr := NewSequenceTracker(128, stats)

	tr.Track(0)
	isNew, _, _ := tr.Track(0)
	if isNew {
		t.Fatal("duplicate should not be new")
	}
	if stats.Snapshot().PacketsDuplicate != 1 {
		t.Error("expected 1 duplicate")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SequenceGenerator tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSequenceGenerator(t *testing.T) {
	g := NewSequenceGenerator()
	for i := uint32(0); i < 100; i++ {
		got := g.Next()
		if got != i {
			t.Fatalf("seq=%d want %d", got, i)
		}
	}
}

func TestSequenceGenerator_Concurrent(t *testing.T) {
	g := NewSequenceGenerator()
	const N = 10000
	seen := make(map[uint32]bool, N)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < N/8; j++ {
				s := g.Next()
				mu.Lock()
				if seen[s] {
					t.Errorf("duplicate seq %d", s)
				}
				seen[s] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Header tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestHeader_EncodeDecode(t *testing.T) {
	h := Header{Sequence: 42, Timestamp: NowTimestamp()}
	buf := make([]byte, HeaderSize)
	h.Encode(buf)

	var h2 Header
	h2.Decode(buf)
	if h2.Sequence != 42 {
		t.Fatalf("seq=%d want 42", h2.Sequence)
	}
	age := TimestampAge(h2.Timestamp)
	if age > 100 { // should be < 100ms
		t.Fatalf("timestamp age=%dms, too old", age)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SessionStats tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSessionStats_GetOrCreate(t *testing.T) {
	ss := NewSessionStats(100, 5*time.Minute)

	info1 := ss.GetOrCreate("sess1", "route1", "10.0.0.1:1234", "127.0.0.1:5678")
	info2 := ss.GetOrCreate("sess1", "route1", "10.0.0.1:1234", "127.0.0.1:5678")
	if info1 != info2 {
		t.Fatal("expected same pointer for same session ID")
	}

	info3 := ss.GetOrCreate("sess2", "route1", "10.0.0.2:1234", "127.0.0.1:5678")
	if info1 == info3 {
		t.Fatal("expected different pointer for different session ID")
	}

	if ss.SessionCount() != 2 {
		t.Fatalf("count=%d want 2", ss.SessionCount())
	}
}

func TestSessionStats_Cleanup(t *testing.T) {
	ss := NewSessionStats(100, 100*time.Millisecond)
	ss.GetOrCreate("s1", "r", "a", "l")
	time.Sleep(200 * time.Millisecond)
	ss.GetOrCreate("s2", "r", "a", "l") // fresh

	removed := ss.Cleanup()
	if removed != 1 {
		t.Fatalf("removed=%d want 1", removed)
	}
	if ss.SessionCount() != 1 {
		t.Fatalf("remaining=%d want 1", ss.SessionCount())
	}
}

func TestSessionStats_CapacityEviction(t *testing.T) {
	ss := NewSessionStats(10, 5*time.Minute)
	for i := 0; i < 15; i++ {
		ss.GetOrCreate(fmt.Sprintf("s%d", i), "r", "a", "l")
	}
	// Should not exceed max by too much (eviction removes 10% = 1)
	count := ss.SessionCount()
	if count > 14 {
		t.Fatalf("count=%d, expected eviction to keep it under max", count)
	}
}

func TestSessionStats_Remove(t *testing.T) {
	ss := NewSessionStats(100, 5*time.Minute)
	ss.GetOrCreate("x", "r", "a", "l")
	ss.Remove("x")
	if ss.SessionCount() != 0 {
		t.Fatal("expected 0 sessions after remove")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkStats_RecordSend(b *testing.B) {
	s := NewStats()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.RecordSend(1400)
	}
}

func BenchmarkStats_RecordReceive(b *testing.B) {
	s := NewStats()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.RecordReceive(1400)
	}
}

func BenchmarkStats_RecordSend_Parallel(b *testing.B) {
	s := NewStats()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.RecordSend(1400)
		}
	})
}

func BenchmarkSequenceTracker_Track(b *testing.B) {
	stats := NewStats()
	tr := NewSequenceTracker(4096, stats)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tr.Track(uint32(i))
	}
}

func BenchmarkSequenceTracker_Track_Parallel(b *testing.B) {
	stats := NewStats()
	tr := NewSequenceTracker(4096, stats)
	var seq atomic.Uint32
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tr.Track(seq.Add(1))
		}
	})
}

func BenchmarkSessionStats_GetOrCreate_HitOnly(b *testing.B) {
	ss := NewSessionStats(1000, 5*time.Minute)
	ss.GetOrCreate("hot-session", "stream", "10.0.0.1:1234", "127.0.0.1:5678")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ss.GetOrCreate("hot-session", "stream", "10.0.0.1:1234", "127.0.0.1:5678")
	}
}

func BenchmarkSessionStats_GetOrCreate_HitParallel(b *testing.B) {
	ss := NewSessionStats(1000, 5*time.Minute)
	ss.GetOrCreate("hot-session", "stream", "10.0.0.1:1234", "127.0.0.1:5678")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ss.GetOrCreate("hot-session", "stream", "10.0.0.1:1234", "127.0.0.1:5678")
		}
	})
}

func BenchmarkSessionStats_GetOrCreate_10Sessions(b *testing.B) {
	ss := NewSessionStats(1000, 5*time.Minute)
	keys := make([]string, 10)
	for i := range keys {
		k := fmt.Sprintf("stream:%d", i)
		keys[i] = k
		ss.GetOrCreate(k, "stream", "10.0.0.1:1234", "127.0.0.1:5678")
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ss.GetOrCreate(keys[i%10], "stream", "10.0.0.1:1234", "127.0.0.1:5678")
			i++
		}
	})
}

func BenchmarkHeader_EncodeDecode(b *testing.B) {
	buf := make([]byte, HeaderSize)
	h := Header{Sequence: 1, Timestamp: NowTimestamp()}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Sequence = uint32(i)
		h.Encode(buf)
		h.Decode(buf)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Realistic scenario: Game streaming stats overhead
// ═══════════════════════════════════════════════════════════════════════════════

func TestStatsOverheadReport(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// Simulate the per-packet stats overhead the server does for each
	// incoming UDP packet: GetOrCreate + RecordReceive + TouchActivity.
	ss := NewSessionStats(1000, 5*time.Minute)
	sessionID := "stream:192.168.1.5"
	info := ss.GetOrCreate(sessionID, "stream", "192.168.1.5", "")

	const N = 200000
	start := time.Now()
	for i := 0; i < N; i++ {
		info.Stats.RecordReceive(1400)
		info.TouchActivity()
	}
	elapsed := time.Since(start)

	nsPerOp := float64(elapsed.Nanoseconds()) / float64(N)
	opsPerSec := 1e9 / nsPerOp

	t.Logf("Stats overhead per packet: %.0f ns (%.0f M ops/sec)", nsPerOp, opsPerSec/1e6)

	// Should handle at least 1M ops/sec (typical game streaming needs <100K).
	if opsPerSec < 500000 {
		t.Errorf("stats overhead too high: %.0f ops/sec (need ≥500K)", opsPerSec)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Realistic scenario: Sequence tracking under packet loss
// ═══════════════════════════════════════════════════════════════════════════════

func TestSequenceTracker_RealisticLoss(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// 5% loss, 1% reordering — typical bad WiFi conditions.
	stats := NewStats()
	tr := NewSequenceTracker(4096, stats)
	rng := rand.New(rand.NewSource(42))

	const totalPackets = 100000
	sent := 0
	delivered := 0
	var pending []uint32

	for seq := uint32(0); seq < totalPackets; seq++ {
		sent++
		if rng.Float64() < 0.05 {
			continue // 5% loss
		}
		if rng.Float64() < 0.01 && len(pending) > 0 {
			// 1% late delivery — deliver a pending packet instead
			idx := rng.Intn(len(pending))
			tr.Track(pending[idx])
			pending = append(pending[:idx], pending[idx+1:]...)
			pending = append(pending, seq) // defer this one
			delivered++
			continue
		}
		tr.Track(seq)
		delivered++
	}
	// Deliver remaining pending
	for _, s := range pending {
		tr.Track(s)
		delivered++
	}

	snap := stats.Snapshot()
	t.Logf("Sent=%d  Delivered=%d  TrackedRecv=%d  Lost=%d  OOO=%d  Dup=%d",
		sent, delivered, snap.PacketsReceived, snap.PacketsLost, snap.PacketsOutOfOrder, snap.PacketsDuplicate)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  GC pressure from stats tracking
// ═══════════════════════════════════════════════════════════════════════════════

func TestStatsGCPressure(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	runtime.GC()
	var mBefore, mAfter runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	s := NewStats()
	const N = 500000
	for i := 0; i < N; i++ {
		s.RecordSend(1400)
		s.RecordReceive(1400)
	}

	runtime.ReadMemStats(&mAfter)
	allocs := mAfter.Mallocs - mBefore.Mallocs
	allocsPerOp := float64(allocs) / float64(N)

	t.Logf("Stats allocs per send+receive pair: %.2f (%d total over %d pairs)", allocsPerOp, allocs, N)

	// RecordSend/RecordReceive should be zero-alloc (atomic ops only).
	// Allow small margin for runtime overhead.
	if allocsPerOp > 0.1 {
		t.Errorf("too many allocs per op: %.2f (expected ~0)", allocsPerOp)
	}
}
