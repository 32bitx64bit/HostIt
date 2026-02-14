package udputil

import (
	"encoding/binary"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
)

// FEC (Forward Error Correction) provides packet loss recovery without retransmission.
// This implementation uses Reed-Solomon erasure coding for proper multi-packet recovery.

// FECConfig configures the FEC encoder/decoder.
type FECConfig struct {
	// DataShards is the number of data packets per FEC group
	DataShards int
	// ParityShards is the number of parity packets per FEC group
	ParityShards int
	// MaxLatency is the maximum time to wait for a complete FEC group
	MaxLatency time.Duration
}

// DefaultFECConfig returns a sensible default FEC configuration.
// 4 data + 2 parity = 50% overhead, can recover up to 2 lost packets per group.
func DefaultFECConfig() FECConfig {
	return FECConfig{
		DataShards:   4,
		ParityShards: 2,
		MaxLatency:   20 * time.Millisecond,
	}
}

// LowLatencyFECConfig returns a low-latency FEC configuration.
// 2 data + 1 parity = 50% overhead, can recover 1 lost packet per group.
func LowLatencyFECConfig() FECConfig {
	return FECConfig{
		DataShards:   2,
		ParityShards: 1,
		MaxLatency:   5 * time.Millisecond,
	}
}

// HighReliabilityFECConfig returns a high-reliability FEC configuration.
// 4 data + 4 parity = 100% overhead, can recover up to 4 lost packets per group.
func HighReliabilityFECConfig() FECConfig {
	return FECConfig{
		DataShards:   4,
		ParityShards: 4,
		MaxLatency:   50 * time.Millisecond,
	}
}

// FECHeader is the header prepended to FEC-encoded packets.
type FECHeader struct {
	GroupID   uint32 // Unique ID for this FEC group
	Index     uint8  // Index within the group (0 = first data, dataShards-1 = last data, dataShards = first parity)
	IsParity  bool   // True if this is a parity packet
	DataLen   uint16 // Length of original data (for decoding)
	TotalData uint8  // Total data shards in this group
	TotalPar  uint8  // Total parity shards in this group
}

const fecHeaderSize = 12

// EncodeFECPacket encodes a packet with FEC header.
func EncodeFECPacket(hdr FECHeader, data []byte) []byte {
	buf := make([]byte, fecHeaderSize+len(data))
	binary.BigEndian.PutUint32(buf[0:4], hdr.GroupID)
	buf[4] = hdr.Index
	if hdr.IsParity {
		buf[5] = 1
	} else {
		buf[5] = 0
	}
	binary.BigEndian.PutUint16(buf[6:8], hdr.DataLen)
	buf[8] = hdr.TotalData
	buf[9] = hdr.TotalPar
	copy(buf[fecHeaderSize:], data)
	return buf
}

// DecodeFECHeader decodes the FEC header from a packet.
func DecodeFECHeader(data []byte) (FECHeader, []byte, bool) {
	if len(data) < fecHeaderSize {
		return FECHeader{}, nil, false
	}
	hdr := FECHeader{
		GroupID:   binary.BigEndian.Uint32(data[0:4]),
		Index:     data[4],
		IsParity:  data[5] == 1,
		DataLen:   binary.BigEndian.Uint16(data[6:8]),
		TotalData: data[8],
		TotalPar:  data[9],
	}
	return hdr, data[fecHeaderSize:], true
}

// FECEncoder encodes packets with forward error correction using Reed-Solomon.
type FECEncoder struct {
	config   FECConfig
	groupID  atomic.Uint32
	groupBuf [][]byte
	groupIdx int
	mu       sync.Mutex

	// Reed-Solomon encoder (cached for reuse)
	encoder reedsolomon.Encoder
}

// NewFECEncoder creates a new FEC encoder.
func NewFECEncoder(config FECConfig) *FECEncoder {
	// Create Reed-Solomon encoder
	enc, err := reedsolomon.New(config.DataShards, config.ParityShards)
	if err != nil {
		// Fallback to a safe default if config is invalid
		enc, _ = reedsolomon.New(4, 2)
		config.DataShards = 4
		config.ParityShards = 2
	}

	return &FECEncoder{
		config:   config,
		groupBuf: make([][]byte, config.DataShards),
		encoder:  enc,
	}
}

// Encode encodes a data packet, returning the encoded packet(s).
// When a group is complete, returns both data and parity packets.
func (e *FECEncoder) Encode(data []byte) [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Store data in group buffer
	e.groupBuf[e.groupIdx] = make([]byte, len(data))
	copy(e.groupBuf[e.groupIdx], data)
	e.groupIdx++

	// If group is complete, generate parity and return all packets
	if e.groupIdx >= e.config.DataShards {
		return e.flushGroup()
	}

	// Return just the data packet
	groupID := e.groupID.Load()
	hdr := FECHeader{
		GroupID:   groupID,
		Index:     uint8(e.groupIdx - 1),
		IsParity:  false,
		DataLen:   uint16(len(data)),
		TotalData: uint8(e.config.DataShards),
		TotalPar:  uint8(e.config.ParityShards),
	}
	return [][]byte{EncodeFECPacket(hdr, data)}
}

// Flush forces completion of the current group, generating parity even if incomplete.
func (e *FECEncoder) Flush() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.groupIdx == 0 {
		return nil
	}
	return e.flushGroup()
}

func (e *FECEncoder) flushGroup() [][]byte {
	groupID := e.groupID.Add(1) - 1

	// Find max data length for padding
	maxLen := 0
	for i := 0; i < e.groupIdx; i++ {
		if len(e.groupBuf[i]) > maxLen {
			maxLen = len(e.groupBuf[i])
		}
	}

	// Pad all data shards to the same length (required by Reed-Solomon)
	shards := make([][]byte, e.config.DataShards+e.config.ParityShards)
	for i := 0; i < e.config.DataShards; i++ {
		if i < e.groupIdx {
			// Copy and pad existing data
			shards[i] = make([]byte, maxLen)
			copy(shards[i], e.groupBuf[i])
		} else {
			// Empty shard for incomplete group
			shards[i] = make([]byte, maxLen)
		}
	}

	// Allocate parity shards
	for i := e.config.DataShards; i < e.config.DataShards+e.config.ParityShards; i++ {
		shards[i] = make([]byte, maxLen)
	}

	// Encode parity using Reed-Solomon
	if err := e.encoder.Encode(shards); err != nil {
		// Fallback to XOR-only encoding on error
		return e.flushGroupXOR(groupID, maxLen)
	}

	// Build output packets
	packets := make([][]byte, 0, e.groupIdx+e.config.ParityShards)

	// Add data packets
	for i := 0; i < e.groupIdx; i++ {
		hdr := FECHeader{
			GroupID:   groupID,
			Index:     uint8(i),
			IsParity:  false,
			DataLen:   uint16(len(e.groupBuf[i])),
			TotalData: uint8(e.groupIdx),
			TotalPar:  uint8(e.config.ParityShards),
		}
		packets = append(packets, EncodeFECPacket(hdr, e.groupBuf[i]))
	}

	// Add parity packets
	for p := 0; p < e.config.ParityShards; p++ {
		hdr := FECHeader{
			GroupID:   groupID,
			Index:     uint8(p),
			IsParity:  true,
			DataLen:   uint16(maxLen),
			TotalData: uint8(e.groupIdx),
			TotalPar:  uint8(e.config.ParityShards),
		}
		packets = append(packets, EncodeFECPacket(hdr, shards[e.config.DataShards+p]))
	}

	// Reset group buffer
	e.groupIdx = 0
	for i := range e.groupBuf {
		e.groupBuf[i] = nil
	}

	return packets
}

// flushGroupXOR is a fallback for when Reed-Solomon encoding fails.
func (e *FECEncoder) flushGroupXOR(groupID uint32, maxLen int) [][]byte {
	packets := make([][]byte, 0, e.groupIdx+e.config.ParityShards)

	// Encode data packets
	for i := 0; i < e.groupIdx; i++ {
		hdr := FECHeader{
			GroupID:   groupID,
			Index:     uint8(i),
			IsParity:  false,
			DataLen:   uint16(len(e.groupBuf[i])),
			TotalData: uint8(e.groupIdx),
			TotalPar:  uint8(e.config.ParityShards),
		}
		packets = append(packets, EncodeFECPacket(hdr, e.groupBuf[i]))
	}

	// Generate parity packets using XOR (simple fallback)
	for p := 0; p < e.config.ParityShards; p++ {
		parity := make([]byte, maxLen)
		for i := 0; i < e.groupIdx; i++ {
			for j := 0; j < len(e.groupBuf[i]); j++ {
				parity[j] ^= e.groupBuf[i][j]
			}
		}

		hdr := FECHeader{
			GroupID:   groupID,
			Index:     uint8(p),
			IsParity:  true,
			DataLen:   uint16(maxLen),
			TotalData: uint8(e.groupIdx),
			TotalPar:  uint8(e.config.ParityShards),
		}
		packets = append(packets, EncodeFECPacket(hdr, parity))
	}

	// Reset group buffer
	e.groupIdx = 0
	for i := range e.groupBuf {
		e.groupBuf[i] = nil
	}

	return packets
}

// FECDecoder decodes FEC-encoded packets and recovers lost data using Reed-Solomon.
type FECDecoder struct {
	config     FECConfig
	groups     map[uint32]*fecGroup
	mu         sync.Mutex
	maxLatency time.Duration

	// Reed-Solomon decoder (cached for reuse)
	decoder reedsolomon.Encoder

	// Stats
	recovered atomic.Uint64
	dropped   atomic.Uint64
}

type fecGroup struct {
	dataPackets   map[uint8][]byte
	parityPackets map[uint8][]byte
	dataLen       uint16
	totalData     uint8
	totalPar      uint8
	createdAt     time.Time
	maxLen        int
}

// NewFECDecoder creates a new FEC decoder.
func NewFECDecoder(config FECConfig) *FECDecoder {
	// Create Reed-Solomon decoder (same interface as encoder)
	dec, err := reedsolomon.New(config.DataShards, config.ParityShards)
	if err != nil {
		dec, _ = reedsolomon.New(4, 2)
		config.DataShards = 4
		config.ParityShards = 2
	}

	return &FECDecoder{
		config:     config,
		groups:     make(map[uint32]*fecGroup),
		maxLatency: config.MaxLatency,
		decoder:    dec,
	}
}

// Process processes an FEC-encoded packet, returning decoded data if available.
// Returns the decoded data, whether recovery occurred, and whether the packet was valid.
func (d *FECDecoder) Process(packet []byte) ([][]byte, bool, bool) {
	hdr, data, ok := DecodeFECHeader(packet)
	if !ok {
		return nil, false, false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Get or create group
	group, exists := d.groups[hdr.GroupID]
	if !exists {
		group = &fecGroup{
			dataPackets:   make(map[uint8][]byte),
			parityPackets: make(map[uint8][]byte),
			totalData:     hdr.TotalData,
			totalPar:      hdr.TotalPar,
			createdAt:     time.Now(),
		}
		d.groups[hdr.GroupID] = group
	}

	// Store packet
	if hdr.IsParity {
		group.parityPackets[hdr.Index] = make([]byte, len(data))
		copy(group.parityPackets[hdr.Index], data)
		if len(data) > group.maxLen {
			group.maxLen = len(data)
		}
	} else {
		group.dataPackets[hdr.Index] = make([]byte, len(data))
		copy(group.dataPackets[hdr.Index], data)
		if group.dataLen == 0 {
			group.dataLen = hdr.DataLen
		}
		if len(data) > group.maxLen {
			group.maxLen = len(data)
		}
	}

	// Check if we have all data packets
	if len(group.dataPackets) >= int(group.totalData) {
		// Complete group - return all data
		delete(d.groups, hdr.GroupID)
		result := make([][]byte, group.totalData)
		for i := uint8(0); i < group.totalData; i++ {
			result[i] = group.dataPackets[i]
		}
		return result, false, true
	}

	// Check if we can recover missing packets
	missing := int(group.totalData) - len(group.dataPackets)
	if missing > 0 && len(group.parityPackets) >= missing {
		// Attempt recovery using Reed-Solomon
		recovered := d.recoverGroup(group)
		if len(recovered) > 0 {
			delete(d.groups, hdr.GroupID)
			d.recovered.Add(uint64(len(recovered) - len(group.dataPackets) + missing))
			return recovered, true, true
		}
	}

	// Check for expired groups
	if time.Since(group.createdAt) > d.maxLatency {
		delete(d.groups, hdr.GroupID)
		d.dropped.Add(1)
		return nil, false, false
	}

	return nil, false, true
}

func (d *FECDecoder) recoverGroup(group *fecGroup) [][]byte {
	totalShards := int(group.totalData) + int(group.totalPar)
	if totalShards == 0 {
		return nil
	}

	// Build shard array for Reed-Solomon reconstruction
	shards := make([][]byte, totalShards)

	// Fill in data shards
	for i := uint8(0); i < group.totalData; i++ {
		if data, exists := group.dataPackets[i]; exists {
			shards[i] = make([]byte, group.maxLen)
			copy(shards[i], data)
		}
		// Missing shards remain nil (Reed-Solomon will reconstruct them)
	}

	// Fill in parity shards
	for i := uint8(0); i < group.totalPar; i++ {
		parityIdx := int(group.totalData) + int(i)
		if data, exists := group.parityPackets[i]; exists {
			shards[parityIdx] = make([]byte, group.maxLen)
			copy(shards[parityIdx], data)
		}
	}

	// Reconstruct missing data shards using Reed-Solomon
	if err := d.decoder.Reconstruct(shards); err != nil {
		// Fallback to XOR recovery for single packet loss
		return d.recoverGroupXOR(group)
	}

	// Verify reconstruction is valid
	ok, err := d.decoder.Verify(shards)
	if err != nil || !ok {
		// Fallback to XOR recovery
		return d.recoverGroupXOR(group)
	}

	// Extract recovered data packets
	result := make([][]byte, group.totalData)
	for i := uint8(0); i < group.totalData; i++ {
		if existing, exists := group.dataPackets[i]; exists {
			result[i] = existing
		} else if shards[i] != nil {
			// Recovered packet - truncate to original length
			dataLen := int(group.dataLen)
			if dataLen > 0 && dataLen < len(shards[i]) {
				result[i] = shards[i][:dataLen]
			} else {
				result[i] = shards[i]
			}
		}
	}

	return result
}

// recoverGroupXOR is a fallback for when Reed-Solomon reconstruction fails.
// It can only recover a single missing packet per group.
func (d *FECDecoder) recoverGroupXOR(group *fecGroup) [][]byte {
	if len(group.parityPackets) == 0 {
		return nil
	}

	// Find missing data packet indices
	missing := make([]uint8, 0)
	for i := uint8(0); i < group.totalData; i++ {
		if _, exists := group.dataPackets[i]; !exists {
			missing = append(missing, i)
		}
	}

	if len(missing) == 0 {
		result := make([][]byte, group.totalData)
		for i := uint8(0); i < group.totalData; i++ {
			result[i] = group.dataPackets[i]
		}
		return result
	}

	// XOR recovery only works for single missing packet
	if len(missing) > 1 {
		return nil
	}

	// Get first parity packet
	var parity []byte
	for _, p := range group.parityPackets {
		parity = p
		break
	}
	if parity == nil {
		return nil
	}

	// XOR all known data with parity to recover missing
	recovered := make([]byte, len(parity))
	copy(recovered, parity)
	for _, data := range group.dataPackets {
		for i := 0; i < len(data) && i < len(recovered); i++ {
			recovered[i] ^= data[i]
		}
	}

	// Truncate to original data length
	if group.dataLen > 0 && int(group.dataLen) < len(recovered) {
		recovered = recovered[:group.dataLen]
	}

	group.dataPackets[missing[0]] = recovered

	// Return all data packets
	result := make([][]byte, group.totalData)
	for i := uint8(0); i < group.totalData; i++ {
		result[i] = group.dataPackets[i]
	}
	return result
}

// Stats returns FEC decoder statistics.
func (d *FECDecoder) Stats() (recovered, dropped uint64) {
	return d.recovered.Load(), d.dropped.Load()
}

// Cleanup removes expired groups.
func (d *FECDecoder) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	for id, group := range d.groups {
		if now.Sub(group.createdAt) > d.maxLatency {
			delete(d.groups, id)
			d.dropped.Add(1)
		}
	}
}

// FECOption controls when FEC is applied.
type FECOption int

const (
	// FECDisabled means no FEC is applied.
	FECDisabled FECOption = iota
	// FECControlOnly applies FEC only to control packets.
	FECControlOnly
	// FECAllPackets applies FEC to all packets.
	FECAllPackets
	// FECAdaptive applies FEC based on observed loss rate.
	FECAdaptive
)

// AdaptiveFEC dynamically adjusts FEC based on network conditions.
type AdaptiveFEC struct {
	config  FECConfig
	option  FECOption
	encoder *FECEncoder
	decoder *FECDecoder

	// Loss tracking (use uint64 bits for float64 atomic)
	lossRateBits atomic.Uint64
	packetsSent  atomic.Uint64
	packetsLost  atomic.Uint64

	// Thresholds
	enableThreshold  float64 // Loss rate to enable FEC
	disableThreshold float64 // Loss rate to disable FEC
}

// NewAdaptiveFEC creates an adaptive FEC controller.
func NewAdaptiveFEC(config FECConfig, option FECOption) *AdaptiveFEC {
	return &AdaptiveFEC{
		config:           config,
		option:           option,
		encoder:          NewFECEncoder(config),
		decoder:          NewFECDecoder(config),
		enableThreshold:  0.01,  // Enable at 1% loss
		disableThreshold: 0.001, // Disable at 0.1% loss
	}
}

// ShouldUseFEC returns true if FEC should be applied based on current conditions.
func (a *AdaptiveFEC) ShouldUseFEC(isControl bool) bool {
	switch a.option {
	case FECDisabled:
		return false
	case FECControlOnly:
		return isControl
	case FECAllPackets:
		return true
	case FECAdaptive:
		return a.getLossRate() >= a.enableThreshold
	}
	return false
}

// RecordLoss records a packet loss for adaptive FEC.
func (a *AdaptiveFEC) RecordLoss() {
	a.packetsLost.Add(1)
	a.updateLossRate()
}

// RecordSend records a packet send for adaptive FEC.
func (a *AdaptiveFEC) RecordSend() {
	a.packetsSent.Add(1)
}

func (a *AdaptiveFEC) updateLossRate() {
	sent := a.packetsSent.Load()
	if sent == 0 {
		return
	}
	lost := a.packetsLost.Load()
	rate := float64(lost) / float64(sent)

	// Exponential moving average
	oldRate := a.getLossRate()
	newRate := oldRate*0.9 + rate*0.1
	a.setLossRate(newRate)
}

// getLossRate returns the current loss rate (thread-safe).
func (a *AdaptiveFEC) getLossRate() float64 {
	bits := a.lossRateBits.Load()
	return math.Float64frombits(bits)
}

// setLossRate sets the loss rate (thread-safe).
func (a *AdaptiveFEC) setLossRate(rate float64) {
	a.lossRateBits.Store(math.Float64bits(rate))
}

// Encoder returns the FEC encoder.
func (a *AdaptiveFEC) Encoder() *FECEncoder {
	return a.encoder
}

// Decoder returns the FEC decoder.
func (a *AdaptiveFEC) Decoder() *FECDecoder {
	return a.decoder
}

// LossRate returns the current estimated loss rate.
func (a *AdaptiveFEC) LossRate() float64 {
	return a.getLossRate()
}

// init seeds the random number generator for FEC
func init() {
	rand.Seed(time.Now().UnixNano())
}
