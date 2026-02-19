package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type AgentNettestRequest struct {
	Count        int
	PayloadBytes int
	Timeout      time.Duration
}

type AgentNettestResult struct {
	AgentConnected bool    `json:"agentConnected"`
	SentPackets    int     `json:"sentPackets"`
	RecvPackets    int     `json:"recvPackets"`
	LostPackets    int     `json:"lostPackets"`
	LossPercent    float64 `json:"lossPercent"`
	AvgLatencyMs   float64 `json:"avgLatencyMs"`
	MinLatencyMs   float64 `json:"minLatencyMs"`
	MaxLatencyMs   float64 `json:"maxLatencyMs"`
	JitterMs       float64 `json:"jitterMs"`
	DurationMs     int64   `json:"durationMs"`
	UploadMbps     float64 `json:"uploadMbps"`
	DownloadMbps   float64 `json:"downloadMbps"`
}

// ThroughputTestResult represents results from a high-throughput streaming test
type ThroughputTestResult struct {
	AgentConnected   bool    `json:"agentConnected"`
	UploadMbps       float64 `json:"uploadMbps"`
	DownloadMbps     float64 `json:"downloadMbps"`
	UploadBytes      int64   `json:"uploadBytes"`
	DownloadBytes    int64   `json:"downloadBytes"`
	UploadDuration   int64   `json:"uploadDurationMs"`
	DownloadDuration int64   `json:"downloadDurationMs"`
	UploadPackets    int64   `json:"uploadPackets"`
	DownloadPackets  int64   `json:"downloadPackets"`
	LossPercent      float64 `json:"lossPercent"`
}

type nettestPong struct {
	id      string
	seq     int
	sendNS  int64
	recvNS  int64
	payload string
}

func (s *Server) RunAgentNettest(ctx context.Context, req AgentNettestRequest) (AgentNettestResult, error) {
	return s.st.runAgentNettest(ctx, req)
}

// RunThroughputTest runs a high-throughput streaming test to measure actual tunnel capacity
func (s *Server) RunThroughputTest(ctx context.Context, duration time.Duration, packetSize int) (ThroughputTestResult, error) {
	return s.st.runThroughputTest(ctx, duration, packetSize)
}

func (st *serverState) runAgentNettest(ctx context.Context, req AgentNettestRequest) (AgentNettestResult, error) {
	st.nettestRunMu.Lock()
	defer st.nettestRunMu.Unlock()

	count := req.Count
	if count <= 0 {
		count = 40
	}
	if count > 400 {
		count = 400
	}
	payloadBytes := req.PayloadBytes
	if payloadBytes <= 0 {
		payloadBytes = 1024
	}
	if payloadBytes > 8192 {
		payloadBytes = 8192
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}

	st.mu.Lock()
	conn := st.agentConn
	st.mu.Unlock()
	if conn == nil {
		return AgentNettestResult{AgentConnected: false}, fmt.Errorf("agent not connected")
	}

	result := AgentNettestResult{AgentConnected: true, SentPackets: count}
	id := newID()
	buf := make([]byte, payloadBytes)
	rtts := make([]float64, 0, count)
	started := time.Now()

	for seq := 1; seq <= count; seq++ {
		if ctx.Err() != nil {
			break
		}
		if _, err := rand.Read(buf); err != nil {
			return result, fmt.Errorf("payload random: %w", err)
		}
		payload := base64.RawStdEncoding.EncodeToString(buf)
		sendNS := time.Now().UnixNano()

		key := nettestKey(id, seq)
		waitCh := make(chan nettestPong, 1)
		st.nettestMu.Lock()
		st.nettestPending[key] = waitCh
		st.nettestMu.Unlock()

		if err := st.agentWriteLinef(conn, "NETTEST_PING %s %d %d %s", id, seq, sendNS, payload); err != nil {
			st.nettestMu.Lock()
			delete(st.nettestPending, key)
			st.nettestMu.Unlock()
			return result, fmt.Errorf("send ping: %w", err)
		}

		select {
		case <-ctx.Done():
			st.nettestMu.Lock()
			delete(st.nettestPending, key)
			st.nettestMu.Unlock()
			return result, ctx.Err()
		case pong := <-waitCh:
			if pong.payload != payload {
				continue
			}
			rttMs := float64(time.Since(time.Unix(0, pong.sendNS)).Microseconds()) / 1000.0
			rtts = append(rtts, rttMs)
			result.RecvPackets++
		case <-time.After(timeout):
			st.nettestMu.Lock()
			delete(st.nettestPending, key)
			st.nettestMu.Unlock()
		}
	}

	elapsed := time.Since(started)
	if elapsed <= 0 {
		elapsed = time.Millisecond
	}
	result.DurationMs = elapsed.Milliseconds()
	result.LostPackets = result.SentPackets - result.RecvPackets
	if result.SentPackets > 0 {
		result.LossPercent = (float64(result.LostPackets) / float64(result.SentPackets)) * 100.0
	}

	if len(rtts) > 0 {
		min := rtts[0]
		max := rtts[0]
		sum := 0.0
		jitterSum := 0.0
		for i, v := range rtts {
			sum += v
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
			if i > 0 {
				d := v - rtts[i-1]
				if d < 0 {
					d = -d
				}
				jitterSum += d
			}
		}
		result.MinLatencyMs = min
		result.MaxLatencyMs = max
		result.AvgLatencyMs = sum / float64(len(rtts))
		if len(rtts) > 1 {
			result.JitterMs = jitterSum / float64(len(rtts)-1)
		}
	}

	uploadBits := float64(result.SentPackets*payloadBytes) * 8.0
	downloadBits := float64(result.RecvPackets*payloadBytes) * 8.0
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 0.001
	}
	result.UploadMbps = uploadBits / seconds / 1e6
	result.DownloadMbps = downloadBits / seconds / 1e6

	return result, nil
}

// runThroughputTest performs a high-throughput streaming test
// This sends packets at a controlled rate to measure tunnel capacity
// without overwhelming the control channel
func (st *serverState) runThroughputTest(ctx context.Context, duration time.Duration, packetSize int) (ThroughputTestResult, error) {
	st.nettestRunMu.Lock()
	defer st.nettestRunMu.Unlock()

	// Defaults
	if duration <= 0 {
		duration = 3 * time.Second
	}
	if duration > 10*time.Second {
		duration = 10 * time.Second
	}
	if packetSize <= 0 {
		packetSize = 1400 // Typical MTU-safe UDP payload
	}
	if packetSize > 65507 {
		packetSize = 65507
	}

	st.mu.Lock()
	conn := st.agentConn
	st.mu.Unlock()
	if conn == nil {
		return ThroughputTestResult{AgentConnected: false}, fmt.Errorf("agent not connected")
	}

	result := ThroughputTestResult{AgentConnected: true}
	id := newID()

	// Create a fixed payload to avoid per-packet random generation overhead
	payload := make([]byte, min(packetSize-100, 4096)) // Leave room for headers
	rand.Read(payload)
	payloadB64 := base64.RawStdEncoding.EncodeToString(payload)

	// Use a single shared channel for ALL responses for this test
	sharedCh := make(chan nettestPong, 100000)

	// Counters for sent packets
	var sentPackets int64
	var sentBytes int64

	// Control channel is not designed for high-throughput.
	// Send at a reasonable rate to avoid overwhelming the agent.
	// Max ~500 packets/second to keep the control channel responsive
	maxPacketsPerSecond := int64(500)
	minInterval := time.Second / time.Duration(maxPacketsPerSecond)

	// Upload phase - send at controlled rate
	uploadStart := time.Now()
	uploadDeadline := uploadStart.Add(duration)
	lastSend := time.Now()

	// Send packets
	for time.Now().Before(uploadDeadline) {
		if ctx.Err() != nil {
			break
		}

		// Rate limit
		elapsed := time.Since(lastSend)
		if elapsed < minInterval {
			time.Sleep(minInterval - elapsed)
		}
		lastSend = time.Now()

		sentPackets++
		sendNS := time.Now().UnixNano()

		// Register this packet with the shared channel
		key := nettestKey(id, int(sentPackets))
		st.nettestMu.Lock()
		st.nettestPending[key] = sharedCh
		st.nettestMu.Unlock()

		if err := st.agentWriteLinef(conn, "NETTEST_PING %s %d %d %s", id, sentPackets, sendNS, payloadB64); err != nil {
			st.nettestMu.Lock()
			delete(st.nettestPending, key)
			st.nettestMu.Unlock()
			break
		}

		sentBytes += int64(len(payloadB64))

		// Drain any responses that have arrived
		for {
			select {
			case <-sharedCh:
				result.DownloadPackets++
				result.DownloadBytes += int64(len(payloadB64))
			default:
				goto continueSending
			}
		}
	continueSending:
	}

	uploadDuration := time.Since(uploadStart)
	result.UploadDuration = uploadDuration.Milliseconds()
	result.UploadPackets = sentPackets
	result.UploadBytes = sentBytes

	// Wait for remaining responses
	waitDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(waitDeadline) {
		select {
		case <-sharedCh:
			result.DownloadPackets++
			result.DownloadBytes += int64(len(payloadB64))
		case <-time.After(200 * time.Millisecond):
			// No more responses coming
			if result.DownloadPackets >= sentPackets {
				goto done
			}
		}
	}

done:
	// Clean up any remaining pending entries for this test
	st.nettestMu.Lock()
	for seq := int64(1); seq <= sentPackets; seq++ {
		delete(st.nettestPending, nettestKey(id, int(seq)))
	}
	st.nettestMu.Unlock()

	result.DownloadDuration = uploadDuration.Milliseconds()

	// Calculate throughput
	uploadSeconds := uploadDuration.Seconds()
	if uploadSeconds <= 0 {
		uploadSeconds = 0.001
	}
	result.UploadMbps = float64(result.UploadBytes*8) / uploadSeconds / 1e6
	result.DownloadMbps = float64(result.DownloadBytes*8) / uploadSeconds / 1e6

	// Calculate loss
	if result.UploadPackets > 0 {
		result.LossPercent = (1.0 - float64(result.DownloadPackets)/float64(result.UploadPackets)) * 100.0
		if result.LossPercent < 0 {
			result.LossPercent = 0
		}
	}

	return result, nil
}

func nettestKey(id string, seq int) string {
	return id + ":" + strconv.Itoa(seq)
}

func (st *serverState) handleNettestPong(rest string) {
	fields := strings.Fields(rest)
	if len(fields) < 5 {
		return
	}
	id := strings.TrimSpace(fields[0])
	seq, err := strconv.Atoi(fields[1])
	if err != nil {
		return
	}
	sendNS, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return
	}
	recvNS, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return
	}
	payload := fields[4]

	key := nettestKey(id, seq)
	st.nettestMu.Lock()
	ch := st.nettestPending[key]
	if ch != nil {
		delete(st.nettestPending, key)
	}
	st.nettestMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- nettestPong{id: id, seq: seq, sendNS: sendNS, recvNS: recvNS, payload: payload}:
	default:
	}
}

func (st *serverState) clearNettestPending() {
	st.nettestMu.Lock()
	for k := range st.nettestPending {
		delete(st.nettestPending, k)
	}
	st.nettestMu.Unlock()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
