package udputil

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// Stats tracks UDP reliability statistics.
type Stats struct {
	// Packets sent/received
	PacketsSent     atomic.Uint64
	PacketsReceived atomic.Uint64
	
	// Bytes sent/received
	BytesSent     atomic.Uint64
	BytesReceived atomic.Uint64
	
	// Reliability metrics
	PacketsLost     atomic.Uint64 // Detected lost packets (gaps in sequence)
	PacketsOutOfOrder atomic.Uint64 // Packets received out of order
	PacketsDuplicate atomic.Uint64 // Duplicate packets received
	
	// Timing metrics
	lastSend    atomic.Int64 // Unix nano
	lastReceive atomic.Int64 // Unix nano
	
	// RTT tracking (for packets with echo)
	rttSum   atomic.Int64 // Sum of RTTs in nanoseconds
	rttCount atomic.Int64 // Number of RTT samples
}

// NewStats creates a new Stats instance.
func NewStats() *Stats {
	return &Stats{}
}

// RecordSend records a packet being sent.
func (s *Stats) RecordSend(bytes int) {
	s.PacketsSent.Add(1)
	s.BytesSent.Add(uint64(bytes))
	s.lastSend.Store(time.Now().UnixNano())
}

// RecordReceive records a packet being received.
func (s *Stats) RecordReceive(bytes int) {
	s.PacketsReceived.Add(1)
	s.BytesReceived.Add(uint64(bytes))
	s.lastReceive.Store(time.Now().UnixNano())
}

// RecordLoss records detected packet loss.
func (s *Stats) RecordLoss(count uint64) {
	s.PacketsLost.Add(count)
}

// RecordOutOfOrder records an out-of-order packet.
func (s *Stats) RecordOutOfOrder() {
	s.PacketsOutOfOrder.Add(1)
}

// RecordDuplicate records a duplicate packet.
func (s *Stats) RecordDuplicate() {
	s.PacketsDuplicate.Add(1)
}

// RecordRTT records a round-trip time measurement.
func (s *Stats) RecordRTT(rtt time.Duration) {
	s.rttSum.Add(int64(rtt))
	s.rttCount.Add(1)
}

// LossRate calculates the packet loss rate (0.0 to 1.0).
func (s *Stats) LossRate() float64 {
	sent := s.PacketsSent.Load()
	if sent == 0 {
		return 0
	}
	lost := s.PacketsLost.Load()
	return float64(lost) / float64(sent)
}

// AvgRTT returns the average round-trip time.
func (s *Stats) AvgRTT() time.Duration {
	count := s.rttCount.Load()
	if count == 0 {
		return 0
	}
	return time.Duration(s.rttSum.Load() / count)
}

// Snapshot returns a point-in-time snapshot of stats.
type StatsSnapshot struct {
	PacketsSent       uint64        `json:"packets_sent"`
	PacketsReceived   uint64        `json:"packets_received"`
	BytesSent         uint64        `json:"bytes_sent"`
	BytesReceived     uint64        `json:"bytes_received"`
	PacketsLost       uint64        `json:"packets_lost"`
	PacketsOutOfOrder uint64        `json:"packets_out_of_order"`
	PacketsDuplicate  uint64        `json:"packets_duplicate"`
	LossRate          float64       `json:"loss_rate"`
	AvgRTT            time.Duration `json:"avg_rtt"`
	LastSend          time.Time     `json:"last_send,omitempty"`
	LastReceive       time.Time     `json:"last_receive,omitempty"`
}

// Snapshot returns a snapshot of current stats.
func (s *Stats) Snapshot() StatsSnapshot {
	snap := StatsSnapshot{
		PacketsSent:       s.PacketsSent.Load(),
		PacketsReceived:   s.PacketsReceived.Load(),
		BytesSent:         s.BytesSent.Load(),
		BytesReceived:     s.BytesReceived.Load(),
		PacketsLost:       s.PacketsLost.Load(),
		PacketsOutOfOrder: s.PacketsOutOfOrder.Load(),
		PacketsDuplicate:  s.PacketsDuplicate.Load(),
		LossRate:          s.LossRate(),
		AvgRTT:            s.AvgRTT(),
	}
	
	if ls := s.lastSend.Load(); ls > 0 {
		snap.LastSend = time.Unix(0, ls)
	}
	if lr := s.lastReceive.Load(); lr > 0 {
		snap.LastReceive = time.Unix(0, lr)
	}
	
	return snap
}

// Reset clears all statistics.
func (s *Stats) Reset() {
	s.PacketsSent.Store(0)
	s.PacketsReceived.Store(0)
	s.BytesSent.Store(0)
	s.BytesReceived.Store(0)
	s.PacketsLost.Store(0)
	s.PacketsOutOfOrder.Store(0)
	s.PacketsDuplicate.Store(0)
	s.lastSend.Store(0)
	s.lastReceive.Store(0)
	s.rttSum.Store(0)
	s.rttCount.Store(0)
}

// SequenceTracker tracks packet sequence numbers to detect loss and reordering.
type SequenceTracker struct {
	mu            sync.Mutex
	expectedSeq   uint32
	highestSeen   uint32
	windowSize    int
	seen          map[uint32]bool // Sliding window of seen sequences
	initialized   bool
	stats         *Stats
}

// NewSequenceTracker creates a tracker with the given window size.
func NewSequenceTracker(windowSize int, stats *Stats) *SequenceTracker {
	if windowSize <= 0 {
		windowSize = 1024
	}
	return &SequenceTracker{
		windowSize: windowSize,
		seen:       make(map[uint32]bool, windowSize),
		stats:      stats,
	}
}

// Track processes a received sequence number.
// Returns: isNew (not duplicate), isOutOfOrder, lostCount
func (t *SequenceTracker) Track(seq uint32) (isNew bool, isOutOfOrder bool, lostCount uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	
	if !t.initialized {
		t.initialized = true
		t.expectedSeq = seq + 1
		t.highestSeen = seq
		t.seen[seq] = true
		if t.stats != nil {
			t.stats.PacketsReceived.Add(1)
		}
		return true, false, 0
	}
	
	// Check for duplicate
	if t.seen[seq] {
		if t.stats != nil {
			t.stats.RecordDuplicate()
		}
		return false, false, 0
	}
	
	// Mark as seen
	t.seen[seq] = true
	if t.stats != nil {
		t.stats.PacketsReceived.Add(1)
	}
	
	// Cleanup old entries outside window
	if len(t.seen) > t.windowSize {
		minSeq := t.highestSeen - uint32(t.windowSize)
		for s := range t.seen {
			if s < minSeq {
				delete(t.seen, s)
			}
		}
	}
	
	// Check for gaps (loss) and out-of-order
	if seq == t.expectedSeq {
		// Perfect - in order
		t.expectedSeq = seq + 1
		if seq > t.highestSeen {
			t.highestSeen = seq
		}
		return true, false, 0
	}
	
	if seq > t.expectedSeq {
		// Gap detected - packets may be lost
		gap := seq - t.expectedSeq
		if t.stats != nil {
			t.stats.RecordLoss(uint64(gap))
		}
		t.expectedSeq = seq + 1
		if seq > t.highestSeen {
			t.highestSeen = seq
		}
		return true, false, gap
	}
	
	// seq < expectedSeq: out of order (late arrival)
	if t.stats != nil {
		t.stats.RecordOutOfOrder()
	}
	return true, true, 0
}

// ExpectedSeq returns the next expected sequence number.
func (t *SequenceTracker) ExpectedSeq() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.expectedSeq
}

// SequenceGenerator generates incrementing sequence numbers.
type SequenceGenerator struct {
	seq atomic.Uint32
}

// NewSequenceGenerator creates a new generator starting at 0.
func NewSequenceGenerator() *SequenceGenerator {
	return &SequenceGenerator{}
}

// Next returns the next sequence number.
func (g *SequenceGenerator) Next() uint32 {
	return g.seq.Add(1) - 1
}

// Current returns the current sequence number without incrementing.
func (g *SequenceGenerator) Current() uint32 {
	return g.seq.Load()
}

// Header constants for UDP reliability header.
const (
	HeaderSize     = 8 // 4 bytes seq + 4 bytes timestamp
	HeaderMagic    = 0xAC // Magic byte to identify packets with reliability header
)

// Header represents a reliability header prepended to UDP packets.
type Header struct {
	Sequence  uint32 // Packet sequence number
	Timestamp uint32 // Sender timestamp (milliseconds, wrapping)
}

// Encode writes the header to a buffer.
func (h *Header) Encode(buf []byte) {
	binary.BigEndian.PutUint32(buf[0:4], h.Sequence)
	binary.BigEndian.PutUint32(buf[4:8], h.Timestamp)
}

// Decode reads the header from a buffer.
func (h *Header) Decode(buf []byte) {
	h.Sequence = binary.BigEndian.Uint32(buf[0:4])
	h.Timestamp = binary.BigEndian.Uint32(buf[4:8])
}

// NowTimestamp returns the current time as a wrapping millisecond timestamp.
func NowTimestamp() uint32 {
	return uint32(time.Now().UnixMilli() & 0xFFFFFFFF)
}

// TimestampAge calculates the age of a timestamp in milliseconds.
func TimestampAge(ts uint32) uint32 {
	now := NowTimestamp()
	if now >= ts {
		return now - ts
	}
	// Handle wrap-around
	return (0xFFFFFFFF - ts) + now + 1
}
