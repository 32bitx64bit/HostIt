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
