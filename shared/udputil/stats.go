package udputil

import (
	"sync/atomic"
	"time"
)

// StatsSnapshot is a point-in-time snapshot of UDP statistics.
type StatsSnapshot struct {
	PacketsSent          uint64  `json:"packets_sent"`
	PacketsReceived      uint64  `json:"packets_received"`
	BytesSent            uint64  `json:"bytes_sent"`
	BytesReceived        uint64  `json:"bytes_received"`
	PacketsLost          uint64  `json:"packets_lost"`
	PacketsOutOfOrder    uint64  `json:"packets_out_of_order"`
	PacketsDuplicate     uint64  `json:"packets_duplicate"`
	AvgRTTMicros         uint64  `json:"avg_rtt_micros"` // Average RTT in microseconds
	TotalRTTSamples      uint64  `json:"total_rtt_samples"`
	EstimatedLossRate    float64 `json:"estimated_loss_rate"`
	EstimatedRTT         uint64  `json:"estimated_rtt_micros"`
	EstimatedBandwidth   uint64  `json:"estimated_bandwidth_bps"`
	ReorderedPackets     uint64  `json:"reordered_packets"`
	LatePackets          uint64  `json:"late_packets"`
	ECNCEMarks           uint64  `json:"ecn_ce_marks"`
	ECNECTMarks          uint64  `json:"ecn_ect_marks"`
	ECNNotECTMarks       uint64  `json:"ecn_not_ect_marks"`
	Retransmissions      uint64  `json:"retransmissions"`
	BytesRetransmitted   uint64  `json:"bytes_retransmitted"`
	FECRecovered         uint64  `json:"fec_recovered"`
	FECPacketsReceived   uint64  `json:"fec_packets_received"`
	FECPacketsDropped    uint64  `json:"fec_packets_dropped"`
	FECCorrectableErrors uint64  `json:"fec_correctable_errors"`
	FECUncorrectable     uint64  `json:"fec_uncorrectable"`
	LossRate             float64 `json:"loss_rate"` // Computed loss rate (0-100)
}

// Stats tracks UDP statistics with zero-allocation methods.
// Fields are exported for direct atomic access where needed.
type Stats struct {
	PacketsSent        atomic.Uint64
	PacketsReceived    atomic.Uint64
	BytesSent          atomic.Uint64
	BytesReceived      atomic.Uint64
	PacketsLost        atomic.Uint64
	PacketsOutOfOrder  atomic.Uint64
	PacketsDuplicate   atomic.Uint64
	rttSumMicros       atomic.Uint64
	rttSamples         atomic.Uint64
	estimatedLossRate  atomic.Uint64 // Stored as fixed-point (0-1 scaled to 0-1e9)
	estimatedRTT       atomic.Uint64 // Microseconds
	estimatedBandwidth atomic.Uint64 // Bytes per second
	reorderedPackets   atomic.Uint64
	latePackets        atomic.Uint64
	ecnCEMarks         atomic.Uint64
	ecnECTMarks        atomic.Uint64
	ecnNotECTMarks     atomic.Uint64
	retransmissions    atomic.Uint64
	bytesRetransmitted atomic.Uint64
	fecRecovered       atomic.Uint64
	fecPacketsReceived atomic.Uint64
	fecPacketsDropped  atomic.Uint64
	fecCorrectable     atomic.Uint64
	fecUncorrectable   atomic.Uint64
}

// NewStats creates a new Stats instance.
func NewStats() *Stats {
	return &Stats{}
}

// RecordSend records a sent packet (zero-allocation).
func (s *Stats) RecordSend(bytes int) {
	s.PacketsSent.Add(1)
	s.BytesSent.Add(uint64(bytes))
}

// RecordReceive records a received packet (zero-allocation).
func (s *Stats) RecordReceive(bytes int) {
	s.PacketsReceived.Add(1)
	s.BytesReceived.Add(uint64(bytes))
}

// RecordLoss records a lost packet.
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

// RecordRTT records an RTT sample.
func (s *Stats) RecordRTT(rtt time.Duration) {
	micros := uint64(rtt.Microseconds())
	s.rttSumMicros.Add(micros)
	s.rttSamples.Add(1)
}

// Snapshot returns a snapshot of the current statistics.
func (s *Stats) Snapshot() StatsSnapshot {
	var snap StatsSnapshot
	snap.PacketsSent = s.PacketsSent.Load()
	snap.PacketsReceived = s.PacketsReceived.Load()
	snap.BytesSent = s.BytesSent.Load()
	snap.BytesReceived = s.BytesReceived.Load()
	snap.PacketsLost = s.PacketsLost.Load()
	snap.PacketsOutOfOrder = s.PacketsOutOfOrder.Load()
	snap.PacketsDuplicate = s.PacketsDuplicate.Load()
	snap.TotalRTTSamples = s.rttSamples.Load()
	snap.AvgRTTMicros = s.rttSumMicros.Load()
	snap.EstimatedLossRate = float64(s.estimatedLossRate.Load()) / 1e9
	snap.EstimatedRTT = s.estimatedRTT.Load()
	snap.EstimatedBandwidth = s.estimatedBandwidth.Load()
	snap.ReorderedPackets = s.reorderedPackets.Load()
	snap.LatePackets = s.latePackets.Load()
	snap.ECNCEMarks = s.ecnCEMarks.Load()
	snap.ECNECTMarks = s.ecnECTMarks.Load()
	snap.ECNNotECTMarks = s.ecnNotECTMarks.Load()
	snap.Retransmissions = s.retransmissions.Load()
	snap.BytesRetransmitted = s.bytesRetransmitted.Load()
	snap.FECRecovered = s.fecRecovered.Load()
	snap.FECPacketsReceived = s.fecPacketsReceived.Load()
	snap.FECPacketsDropped = s.fecPacketsDropped.Load()
	snap.FECCorrectableErrors = s.fecCorrectable.Load()
	snap.FECUncorrectable = s.fecUncorrectable.Load()
	// Compute loss rate
	sent := s.PacketsSent.Load()
	if sent > 0 {
		snap.LossRate = float64(s.PacketsLost.Load()) / float64(sent) * 100
	}
	return snap
}

// LossRate returns the estimated loss rate (0-1).
func (s *Stats) LossRate() float64 {
	sent := s.PacketsSent.Load()
	if sent == 0 {
		return 0
	}
	lost := s.PacketsLost.Load()
	return float64(lost) / float64(sent)
}

// AvgRTT returns the average RTT.
func (s *Stats) AvgRTT() time.Duration {
	samples := s.rttSamples.Load()
	if samples == 0 {
		return 0
	}
	sum := s.rttSumMicros.Load()
	return time.Duration(sum/samples) * time.Microsecond
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
	s.rttSumMicros.Store(0)
	s.rttSamples.Store(0)
	s.estimatedLossRate.Store(0)
	s.estimatedRTT.Store(0)
	s.estimatedBandwidth.Store(0)
	s.reorderedPackets.Store(0)
	s.latePackets.Store(0)
	s.ecnCEMarks.Store(0)
	s.ecnECTMarks.Store(0)
	s.ecnNotECTMarks.Store(0)
	s.retransmissions.Store(0)
	s.bytesRetransmitted.Store(0)
	s.fecRecovered.Store(0)
	s.fecPacketsReceived.Store(0)
	s.fecPacketsDropped.Store(0)
	s.fecCorrectable.Store(0)
	s.fecUncorrectable.Store(0)
}

// RecordReordered records a reordered packet.
func (s *Stats) RecordReordered() {
	s.reorderedPackets.Add(1)
}

// RecordLate records a late packet.
func (s *Stats) RecordLate() {
	s.latePackets.Add(1)
}

// RecordECNMark records an ECN mark.
func (s *Stats) RecordECNMark(ce, ect, notECT bool) {
	if ce {
		s.ecnCEMarks.Add(1)
	}
	if ect {
		s.ecnECTMarks.Add(1)
	}
	if notECT {
		s.ecnNotECTMarks.Add(1)
	}
}

// RecordRetransmission records a retransmission.
func (s *Stats) RecordRetransmission(bytes int) {
	s.retransmissions.Add(1)
	s.bytesRetransmitted.Add(uint64(bytes))
}

// RecordFECRecovered records a packet recovered via FEC.
func (s *Stats) RecordFECRecovered() {
	s.fecRecovered.Add(1)
}

// RecordFECPacket records an FEC packet.
func (s *Stats) RecordFECPacket(dropped bool) {
	s.fecPacketsReceived.Add(1)
	if dropped {
		s.fecPacketsDropped.Add(1)
	}
}

// RecordFECResult records FEC correction results.
func (s *Stats) RecordFECResult(correctable, uncorrectable bool) {
	if correctable {
		s.fecCorrectable.Add(1)
	}
	if uncorrectable {
		s.fecUncorrectable.Add(1)
	}
}

// SetEstimatedLossRate sets the estimated loss rate (0-1).
func (s *Stats) SetEstimatedLossRate(rate float64) {
	if rate < 0 {
		rate = 0
	} else if rate > 1 {
		rate = 1
	}
	s.estimatedLossRate.Store(uint64(rate * 1e9))
}

// SetEstimatedRTT sets the estimated RTT.
func (s *Stats) SetEstimatedRTT(rtt time.Duration) {
	s.estimatedRTT.Store(uint64(rtt.Microseconds()))
}

// SetEstimatedBandwidth sets the estimated bandwidth in bytes/sec.
func (s *Stats) SetEstimatedBandwidth(bps uint64) {
	s.estimatedBandwidth.Store(bps)
}

// Merge merges another Stats into this one.
func (s *Stats) Merge(other *Stats) {
	if other == nil {
		return
	}
	s.PacketsSent.Add(other.PacketsSent.Load())
	s.PacketsReceived.Add(other.PacketsReceived.Load())
	s.BytesSent.Add(other.BytesSent.Load())
	s.BytesReceived.Add(other.BytesReceived.Load())
	s.PacketsLost.Add(other.PacketsLost.Load())
	s.PacketsOutOfOrder.Add(other.PacketsOutOfOrder.Load())
	s.PacketsDuplicate.Add(other.PacketsDuplicate.Load())
	s.rttSumMicros.Add(other.rttSumMicros.Load())
	s.rttSamples.Add(other.rttSamples.Load())
	s.reorderedPackets.Add(other.reorderedPackets.Load())
	s.latePackets.Add(other.latePackets.Load())
	s.ecnCEMarks.Add(other.ecnCEMarks.Load())
	s.ecnECTMarks.Add(other.ecnECTMarks.Load())
	s.ecnNotECTMarks.Add(other.ecnNotECTMarks.Load())
	s.retransmissions.Add(other.retransmissions.Load())
	s.bytesRetransmitted.Add(other.bytesRetransmitted.Load())
	s.fecRecovered.Add(other.fecRecovered.Load())
	s.fecPacketsReceived.Add(other.fecPacketsReceived.Load())
	s.fecPacketsDropped.Add(other.fecPacketsDropped.Load())
	s.fecCorrectable.Add(other.fecCorrectable.Load())
	s.fecUncorrectable.Add(other.fecUncorrectable.Load())
}

// Header represents a UDP packet header with sequence and timestamp.
type Header struct {
	Sequence  uint32
	Timestamp uint64
}

// HeaderSize is the size of the UDP header in bytes.
const HeaderSize = 12

// Encode encodes the header into buf (must be at least HeaderSize bytes).
func (h *Header) Encode(buf []byte) {
	binaryPutUint32(buf[0:4], h.Sequence)
	binaryPutUint64(buf[4:12], h.Timestamp)
}

// Decode decodes the header from buf (must be at least HeaderSize bytes).
func (h *Header) Decode(buf []byte) {
	h.Sequence = binaryGetUint32(buf[0:4])
	h.Timestamp = binaryGetUint64(buf[4:12])
}

// NowTimestamp returns the current time as a timestamp (microseconds since epoch).
func NowTimestamp() uint64 {
	return uint64(time.Now().UnixNano() / 1000)
}

// TimestampAge returns the age of a timestamp in milliseconds.
func TimestampAge(ts uint64) int64 {
	now := uint64(time.Now().UnixNano() / 1000)
	return int64((now - ts) / 1000)
}

// Helper functions for binary encoding/decoding without importing encoding/binary

// binaryPutUint32 puts a uint32 in big-endian format.
func binaryPutUint32(b []byte, v uint32) {
	_ = b[3] // bounds check
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// binaryGetUint32 gets a uint32 from big-endian format.
func binaryGetUint32(b []byte) uint32 {
	_ = b[3] // bounds check
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// binaryPutUint64 puts a uint64 in big-endian format.
func binaryPutUint64(b []byte, v uint64) {
	_ = b[7] // bounds check
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

// binaryGetUint64 gets a uint64 from big-endian format.
func binaryGetUint64(b []byte) uint64 {
	_ = b[7] // bounds check
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}
