// Package udputil provides high-throughput UDP utilities for tunnel systems.
// It includes packet encoding/decoding, encryption, buffer pooling, and session tracking.
package udputil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Packet Type Constants
// ============================================================================

// Packet type constants - first byte of each packet identifies its type
const (
	TypeRegister byte = 0x01 // Agent registration packet
	TypeData     byte = 0x02 // Data packet (carries payload)
	TypeAck      byte = 0x03 // Acknowledgment packet
	TypePing     byte = 0x04 // Keepalive ping
	TypePong     byte = 0x05 // Keepalive pong
)

// Maximum sizes for protocol fields
const (
	MaxRouteLen   = 64
	MaxClientLen  = 128 // IP:port can be up to ~50 chars, allow more for future
	MaxTokenLen   = 256
	MaxPayloadLen = 65507 // Max UDP payload size
)

// ============================================================================
// Packet Encoding/Decoding
// ============================================================================

// EncodeRegister creates a registration packet with the given token.
// Format: [TypeRegister(1)] [token_len(2)] [token(N)]
func EncodeRegister(token string) []byte {
	tok := []byte(token)
	if len(tok) > MaxTokenLen {
		tok = tok[:MaxTokenLen]
	}

	buf := make([]byte, 1+2+len(tok))
	buf[0] = TypeRegister
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(tok)))
	copy(buf[3:], tok)
	return buf
}

// DecodeRegister extracts the token from a registration packet.
// Returns the token and true if successful, empty string and false otherwise.
func DecodeRegister(pkt []byte) (string, bool) {
	if len(pkt) < 3 {
		return "", false
	}
	if pkt[0] != TypeRegister {
		return "", false
	}
	tokLen := int(binary.BigEndian.Uint16(pkt[1:3]))
	if len(pkt) < 3+tokLen {
		return "", false
	}
	return string(pkt[3 : 3+tokLen]), true
}

// EncodeData creates a data packet with route, client address, and payload.
// Format: [TypeData(1)] [route_len(1)] [route(N)] [client_len(1)] [client(M)] [payload(...)]
func EncodeData(route, client string, payload []byte) []byte {
	routeBytes := []byte(route)
	clientBytes := []byte(client)

	if len(routeBytes) > MaxRouteLen {
		routeBytes = routeBytes[:MaxRouteLen]
	}
	if len(clientBytes) > MaxClientLen {
		clientBytes = clientBytes[:MaxClientLen]
	}

	totalLen := 1 + 1 + len(routeBytes) + 1 + len(clientBytes) + len(payload)
	buf := make([]byte, totalLen)

	i := 0
	buf[i] = TypeData
	i++

	buf[i] = byte(len(routeBytes))
	i++
	copy(buf[i:], routeBytes)
	i += len(routeBytes)

	buf[i] = byte(len(clientBytes))
	i++
	copy(buf[i:], clientBytes)
	i += len(clientBytes)

	copy(buf[i:], payload)
	return buf
}

// DecodeData extracts route, client, and payload from a data packet.
// Returns route, client, payload, and true if successful.
// Returns empty values and false if the packet is malformed.
func DecodeData(pkt []byte) (route, client string, payload []byte, ok bool) {
	if len(pkt) < 4 {
		return "", "", nil, false
	}
	if pkt[0] != TypeData {
		return "", "", nil, false
	}

	i := 1
	routeLen := int(pkt[i])
	i++

	if len(pkt) < i+routeLen+2 {
		return "", "", nil, false
	}
	route = string(pkt[i : i+routeLen])
	i += routeLen

	clientLen := int(pkt[i])
	i++

	if len(pkt) < i+clientLen {
		return "", "", nil, false
	}
	client = string(pkt[i : i+clientLen])
	i += clientLen

	payload = pkt[i:]
	return route, client, payload, true
}

// EncodePing creates a ping packet with a timestamp for RTT measurement.
// Format: [TypePing(1)] [timestamp_ns(8)]
func EncodePing(timestamp int64) []byte {
	buf := make([]byte, 9)
	buf[0] = TypePing
	binary.BigEndian.PutUint64(buf[1:9], uint64(timestamp))
	return buf
}

// DecodePing extracts the timestamp from a ping packet.
func DecodePing(pkt []byte) (int64, bool) {
	if len(pkt) < 9 {
		return 0, false
	}
	if pkt[0] != TypePing {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(pkt[1:9])), true
}

// EncodePong creates a pong response packet.
// Format: [TypePong(1)] [timestamp_ns(8)]
func EncodePong(timestamp int64) []byte {
	buf := make([]byte, 9)
	buf[0] = TypePong
	binary.BigEndian.PutUint64(buf[1:9], uint64(timestamp))
	return buf
}

// DecodePong extracts the timestamp from a pong packet.
func DecodePong(pkt []byte) (int64, bool) {
	if len(pkt) < 9 {
		return 0, false
	}
	if pkt[0] != TypePong {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(pkt[1:9])), true
}

// ============================================================================
// Encryption (AES-GCM)
// ============================================================================

var (
	ErrInvalidKeySize    = errors.New("invalid key size")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrDecryptFailed     = errors.New("decryption failed")
)

// KeySet manages encryption keys with support for key rotation
type KeySet struct {
	mu          sync.RWMutex
	currentKey  []byte
	currentID   uint32
	prevKey     []byte
	prevID      uint32
	currentAEAD cipher.AEAD
	prevAEAD    cipher.AEAD
	salt        []byte
	mode        string
}

// NewKeySet creates a new KeySet from the given parameters
func NewKeySet(mode, token string, keyID uint32, salt []byte, prevKeyID uint32, prevSalt []byte) (*KeySet, error) {
	ks := &KeySet{
		currentID: keyID,
		prevID:    prevKeyID,
		mode:      strings.ToLower(strings.TrimSpace(mode)),
	}

	if ks.mode == "" || ks.mode == "none" {
		return ks, nil
	}

	// Derive key from token and salt
	if len(salt) > 0 {
		ks.salt = salt
		currentKey := deriveKey(token, salt)
		aead, err := createAEAD(currentKey)
		if err != nil {
			return nil, err
		}
		ks.currentKey = currentKey
		ks.currentAEAD = aead
	}

	// Previous key for rotation
	if len(prevSalt) > 0 && prevKeyID > 0 {
		prevKey := deriveKey(token, prevSalt)
		aead, err := createAEAD(prevKey)
		if err != nil {
			return nil, err
		}
		ks.prevKey = prevKey
		ks.prevAEAD = aead
	}

	return ks, nil
}

// HasKey returns true if encryption is enabled
func (ks *KeySet) HasKey() bool {
	if ks == nil {
		return false
	}
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.currentAEAD != nil
}

// Encrypt encrypts the plaintext using AES-GCM
func (ks *KeySet) Encrypt(plaintext []byte) []byte {
	if ks == nil || ks.currentAEAD == nil {
		return plaintext
	}

	ks.mu.RLock()
	aead := ks.currentAEAD
	keyID := ks.currentID
	ks.mu.RUnlock()

	// Allocate buffer: keyID(4) + nonce(12) + ciphertext + tag(16)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plaintext // fallback to plaintext on error
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Format: [keyID(4)] [nonce(12)] [ciphertext+tag]
	result := make([]byte, 4+12+len(ciphertext))
	binary.BigEndian.PutUint32(result[0:4], keyID)
	copy(result[4:16], nonce)
	copy(result[16:], ciphertext)
	return result
}

// Decrypt decrypts the ciphertext using AES-GCM
func (ks *KeySet) Decrypt(ciphertext []byte) ([]byte, bool) {
	if ks == nil {
		return nil, false
	}

	ks.mu.RLock()
	currentAEAD := ks.currentAEAD
	currentID := ks.currentID
	prevAEAD := ks.prevAEAD
	prevID := ks.prevID
	ks.mu.RUnlock()

	if currentAEAD == nil {
		return ciphertext, true // no encryption
	}

	if len(ciphertext) < 4+12+16 { // keyID + nonce + tag
		return nil, false
	}

	keyID := binary.BigEndian.Uint32(ciphertext[0:4])
	nonce := ciphertext[4:16]
	data := ciphertext[16:]

	// Try current key first
	if keyID == currentID && currentAEAD != nil {
		plaintext, err := currentAEAD.Open(nil, nonce, data, nil)
		if err == nil {
			return plaintext, true
		}
	}

	// Try previous key
	if keyID == prevID && prevAEAD != nil {
		plaintext, err := prevAEAD.Open(nil, nonce, data, nil)
		if err == nil {
			return plaintext, true
		}
	}

	return nil, false
}

func deriveKey(token string, salt []byte) []byte {
	// Simple key derivation: hash token with salt
	// In production, use a proper KDF like HKDF
	key := make([]byte, 32)
	tokenBytes := []byte(token)
	for i := 0; i < 32; i++ {
		if i < len(salt) {
			key[i] = salt[i]
		}
		if i < len(tokenBytes) {
			key[i] ^= tokenBytes[i]
		}
	}
	return key
}

func createAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ============================================================================
// Buffer Pools
// ============================================================================

var (
	// Small buffer pool for packets up to 1KB
	smallPool = sync.Pool{
		New: func() any {
			b := make([]byte, 1024)
			return &b
		},
	}

	// Medium buffer pool for packets up to 4KB
	mediumPool = sync.Pool{
		New: func() any {
			b := make([]byte, 4096)
			return &b
		},
	}

	// Large buffer pool for packets up to 16KB
	largePool = sync.Pool{
		New: func() any {
			b := make([]byte, 16384)
			return &b
		},
	}

	// XL buffer pool for packets up to 64KB (max UDP)
	xlPool = sync.Pool{
		New: func() any {
			b := make([]byte, 65536)
			return &b
		},
	}
)

// GetBuffer returns a buffer from the appropriate pool based on size hint
func GetBuffer(size int) *[]byte {
	switch {
	case size <= 1024:
		return smallPool.Get().(*[]byte)
	case size <= 4096:
		return mediumPool.Get().(*[]byte)
	case size <= 16384:
		return largePool.Get().(*[]byte)
	default:
		return xlPool.Get().(*[]byte)
	}
}

// PutBuffer returns a buffer to the appropriate pool based on its capacity
func PutBuffer(b *[]byte) {
	if b == nil {
		return
	}
	c := cap(*b)
	switch {
	case c <= 1024:
		smallPool.Put(b)
	case c <= 4096:
		mediumPool.Put(b)
	case c <= 16384:
		largePool.Put(b)
	default:
		xlPool.Put(b)
	}
}

// ============================================================================
// Elastic Buffer Pool
// ============================================================================

// ElasticBuffer is a buffer that can be resized efficiently
type ElasticBuffer struct {
	data []byte
	size int
}

// Data returns the underlying byte slice
func (eb *ElasticBuffer) Data() []byte {
	if eb == nil {
		return nil
	}
	return eb.data[:eb.size]
}

// SetSize sets the logical size of the buffer
func (eb *ElasticBuffer) SetSize(n int) {
	if eb != nil && n <= cap(eb.data) {
		eb.size = n
	}
}

// Cap returns the capacity of the underlying buffer
func (eb *ElasticBuffer) Cap() int {
	if eb == nil {
		return 0
	}
	return cap(eb.data)
}

// Put returns the ElasticBuffer to a pool (for interface compatibility)
func (eb *ElasticBuffer) Put() {
	// ElasticBuffer is managed by ElasticBufferPool
}

// ElasticBufferPool manages elastic buffers with multiple size classes
type ElasticBufferPool struct {
	pools [5]sync.Pool
	sizes [5]int
}

// NewElasticBufferPool creates a new elastic buffer pool
func NewElasticBufferPool() *ElasticBufferPool {
	p := &ElasticBufferPool{
		sizes: [5]int{512, 2048, 8192, 32768, 65536},
	}
	for i := range p.sizes {
		size := p.sizes[i]
		p.pools[i].New = func() any {
			return &ElasticBuffer{
				data: make([]byte, size),
			}
		}
	}
	return p
}

// Get returns an ElasticBuffer with at least the requested capacity
func (p *ElasticBufferPool) Get(minCap int) *ElasticBuffer {
	// Find the smallest pool that can satisfy the request
	for i, size := range p.sizes {
		if size >= minCap {
			eb := p.pools[i].Get().(*ElasticBuffer)
			eb.size = 0
			return eb
		}
	}
	// Fallback: create a new buffer
	return &ElasticBuffer{
		data: make([]byte, minCap),
	}
}

// ============================================================================
// Session Stats
// ============================================================================

// SessionStats tracks statistics for a UDP session
type SessionStats struct {
	PacketsReceived atomic.Uint64
	BytesReceived   atomic.Uint64
	PacketsSent     atomic.Uint64
	BytesSent       atomic.Uint64
	LastActivity    atomic.Int64 // Unix nano
}

// RecordReceive records a received packet
func (s *SessionStats) RecordReceive(n int) {
	s.PacketsReceived.Add(1)
	s.BytesReceived.Add(uint64(n))
	s.LastActivity.Store(time.Now().UnixNano())
}

// RecordSend records a sent packet
func (s *SessionStats) RecordSend(n int) {
	s.PacketsSent.Add(1)
	s.BytesSent.Add(uint64(n))
	s.LastActivity.Store(time.Now().UnixNano())
}

// SessionInfo contains information about a UDP session
type SessionInfo struct {
	ID         string
	Route      string
	ClientIP   string
	ServerAddr string
	Stats      *SessionStats
	Created    time.Time
}

// TouchActivity updates the last activity timestamp
func (si *SessionInfo) TouchActivity() {
	if si.Stats != nil {
		si.Stats.LastActivity.Store(time.Now().UnixNano())
	}
}

// SessionStatsMap is a thread-safe map for session statistics
type SessionStatsMap struct {
	mu       sync.RWMutex
	sessions map[string]*SessionInfo
	maxSize  int
	ttl      time.Duration
}

// NewSessionStats creates a new SessionStatsMap
func NewSessionStats(maxSize int, ttl time.Duration) *SessionStatsMap {
	return &SessionStatsMap{
		sessions: make(map[string]*SessionInfo),
		maxSize:  maxSize,
		ttl:      ttl,
	}
}

// GetOrCreate gets or creates a session info
func (m *SessionStatsMap) GetOrCreate(id, route, clientIP, serverAddr string) *SessionInfo {
	m.mu.RLock()
	info, ok := m.sessions[id]
	m.mu.RUnlock()

	if ok {
		return info
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check
	if info, ok = m.sessions[id]; ok {
		return info
	}

	// Evict old entries if at capacity
	if len(m.sessions) >= m.maxSize {
		now := time.Now()
		for k, v := range m.sessions {
			if now.Sub(v.Created) > m.ttl {
				delete(m.sessions, k)
			}
		}
	}

	info = &SessionInfo{
		ID:         id,
		Route:      route,
		ClientIP:   clientIP,
		ServerAddr: serverAddr,
		Stats:      &SessionStats{},
		Created:    time.Now(),
	}
	m.sessions[id] = info
	return info
}

// Summary returns a summary of all sessions
type SessionSummary struct {
	TotalSessions int
	ByRoute       map[string]int
	TotalPackets  uint64
	TotalBytes    uint64
}

// Summary returns a summary of all sessions
func (m *SessionStatsMap) Summary() *SessionSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	summary := &SessionSummary{
		TotalSessions: len(m.sessions),
		ByRoute:       make(map[string]int),
	}

	for _, info := range m.sessions {
		summary.ByRoute[info.Route]++
		summary.TotalPackets += info.Stats.PacketsReceived.Load() + info.Stats.PacketsSent.Load()
		summary.TotalBytes += info.Stats.BytesReceived.Load() + info.Stats.BytesSent.Load()
	}

	return summary
}

// ============================================================================
// Utility Functions
// ============================================================================

// ValidateRoute checks if a route name is valid
func ValidateRoute(route string) bool {
	route = strings.TrimSpace(route)
	if route == "" || len(route) > MaxRouteLen {
		return false
	}
	for _, c := range route {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

// ValidateClientAddr checks if a client address string is valid
func ValidateClientAddr(client string) bool {
	client = strings.TrimSpace(client)
	if client == "" || len(client) > MaxClientLen {
		return false
	}
	return true
}
