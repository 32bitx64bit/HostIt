package udpproto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
//  End-to-end UDP relay benchmark
//
//  Simulates the real Sunshine/Moonlight game streaming flow:
//
//    Sunshine (local) --(UDP)--> Agent encode --(UDP socket)--> Server decode
//    --> Server re-encode --(UDP socket)--> Client decode --(UDP)--> Moonlight
//
//  Uses real UDP sockets on loopback to capture actual kernel+syscall costs.
// ═══════════════════════════════════════════════════════════════════════════════

// relayPair sets up a pair of local UDP sockets connected through an
// encode→send→recv→decode relay, simulating one leg of the tunnel.
type relayPair struct {
	// "source" sends raw payloads; "sink" receives decoded payloads.
	source *net.UDPConn // Sunshine/Moonlight side
	sink   *net.UDPConn // local service side

	// Internal relay sockets
	relayRecv *net.UDPConn // receives from source
	relaySend *net.UDPConn // sends to sink

	cancel chan struct{}
	ks     KeySet
	route  string
	client string
}

func newRelayPair(t testing.TB, encrypted bool) *relayPair {
	t.Helper()

	// Source → relayRecv (simulates Sunshine → Agent)
	sourceAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	relayRecvConn, err := net.ListenUDP("udp", sourceAddr)
	if err != nil {
		t.Fatal(err)
	}

	// relaySend → sink (simulates Server → Client's Moonlight)
	sinkAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	sinkConn, err := net.ListenUDP("udp", sinkAddr)
	if err != nil {
		t.Fatal(err)
	}
	relaySendAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	relaySendConn, err := net.ListenUDP("udp", relaySendAddr)
	if err != nil {
		t.Fatal(err)
	}

	// Source connects to relayRecv
	sourceConn, err := net.DialUDP("udp", nil, relayRecvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	var ks KeySet
	if encrypted {
		ks = mustKeySet(t, ModeAES256)
	}

	rp := &relayPair{
		source:    sourceConn,
		sink:      sinkConn,
		relayRecv: relayRecvConn,
		relaySend: relaySendConn,
		cancel:    make(chan struct{}),
		ks:        ks,
		route:     "stream",
		client:    "192.168.1.5:47821",
	}

	// Set buffer sizes
	for _, c := range []*net.UDPConn{sourceConn, sinkConn, relayRecvConn, relaySendConn} {
		_ = c.SetReadBuffer(4 * 1024 * 1024)
		_ = c.SetWriteBuffer(4 * 1024 * 1024)
	}

	return rp
}

// startRelay runs a goroutine that reads from relayRecv, encodes, sends to sink.
func (rp *relayPair) startRelay(t testing.TB) {
	t.Helper()
	sinkTarget := rp.sink.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 64*1024)
		for {
			select {
			case <-rp.cancel:
				return
			default:
			}
			_ = rp.relayRecv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _, err := rp.relayRecv.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			raw := buf[:n]

			// Simulate server processing: decode then re-encode.
			var payload []byte
			if rp.ks.Enabled() {
				// Encode as agent → server
				wire := EncodeDataEnc2ForKeyID(rp.ks, rp.ks.CurID, rp.route, rp.client, raw)
				// Decode at server
				_, _, p, _, ok := DecodeDataEnc2(rp.ks, wire)
				if !ok {
					continue
				}
				payload = p
			} else {
				wire := EncodeData(rp.route, rp.client, raw)
				_, _, p, ok := DecodeData(wire)
				if !ok {
					continue
				}
				payload = p
			}
			// Forward to sink
			_, _ = rp.relaySend.WriteToUDP(payload, sinkTarget)
		}
	}()
}

func (rp *relayPair) close() {
	close(rp.cancel)
	rp.source.Close()
	rp.sink.Close()
	rp.relayRecv.Close()
	rp.relaySend.Close()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Throughput test: saturate the relay and measure actual Mbps
// ═══════════════════════════════════════════════════════════════════════════════

func TestUDPRelayThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	scenarios := []struct {
		name      string
		pktSize   int
		encrypted bool
	}{
		{"Video_1400B_Encrypted", 1400, true},
		{"Video_1400B_Plaintext", 1400, false},
		{"Audio_480B_Encrypted", 480, true},
		{"Input_32B_Encrypted", 32, true},
	}

	t.Logf("\n%-30s %8s %8s %10s %10s", "Scenario", "Sent", "Recv", "Loss%", "Mbps")
	t.Logf("%-30s %8s %8s %10s %10s", "--------", "----", "----", "-----", "----")

	for _, sc := range scenarios {
		rp := newRelayPair(t, sc.encrypted)
		rp.startRelay(t)

		payload := make([]byte, sc.pktSize)
		rand.Read(payload)

		const duration = 2 * time.Second
		deadline := time.Now().Add(duration)
		var sent, recv atomic.Int64

		// Receiver goroutine
		recvDone := make(chan struct{})
		go func() {
			defer close(recvDone)
			buf := make([]byte, 64*1024)
			for {
				_ = rp.sink.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, _, err := rp.sink.ReadFromUDP(buf)
				if err != nil {
					if time.Now().After(deadline.Add(1 * time.Second)) {
						return
					}
					continue
				}
				if n > 0 {
					recv.Add(1)
				}
			}
		}()

		// Sender — blast as fast as possible
		start := time.Now()
		for time.Now().Before(deadline) {
			_, err := rp.source.Write(payload)
			if err != nil {
				break
			}
			sent.Add(1)
		}
		elapsed := time.Since(start)

		// Wait for receiver to drain
		time.Sleep(500 * time.Millisecond)
		rp.close()
		<-recvDone

		s := sent.Load()
		r := recv.Load()
		loss := float64(s-r) / float64(s) * 100
		mbps := float64(r) * float64(sc.pktSize) * 8 / elapsed.Seconds() / 1e6

		t.Logf("%-30s %8d %8d %9.1f%% %10.1f", sc.name, s, r, loss, mbps)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Latency test: measure per-packet relay latency with sequence numbers
// ═══════════════════════════════════════════════════════════════════════════════

func TestUDPRelayLatency(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	rp := newRelayPair(t, true)
	rp.startRelay(t)
	defer rp.close()

	const N = 5000
	latencies := make([]time.Duration, 0, N)
	payload := make([]byte, 1400)

	for i := 0; i < N; i++ {
		// Embed send timestamp in payload
		now := time.Now()
		copy(payload[:8], encodeNanos(now.UnixNano()))

		_, err := rp.source.Write(payload)
		if err != nil {
			continue
		}

		buf := make([]byte, 64*1024)
		_ = rp.sink.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := rp.sink.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n >= 8 {
			sendNanos := decodeNanos(buf[:8])
			lat := time.Since(time.Unix(0, sendNanos))
			latencies = append(latencies, lat)
		}
	}

	if len(latencies) < N/2 {
		t.Fatalf("too few packets received: %d/%d", len(latencies), N)
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50 := latencies[len(latencies)*50/100]
	p95 := latencies[len(latencies)*95/100]
	p99 := latencies[len(latencies)*99/100]

	t.Logf("UDP relay latency (%d samples): P50=%v, P95=%v, P99=%v",
		len(latencies), p50, p95, p99)

	// Loopback with encode/decode should be well under 1ms.
	if p50 > 2*time.Millisecond {
		t.Errorf("P50 latency %v too high (expected <2ms on loopback)", p50)
	}
}

func encodeNanos(n int64) []byte {
	b := make([]byte, 8)
	b[0] = byte(n >> 56)
	b[1] = byte(n >> 48)
	b[2] = byte(n >> 40)
	b[3] = byte(n >> 32)
	b[4] = byte(n >> 24)
	b[5] = byte(n >> 16)
	b[6] = byte(n >> 8)
	b[7] = byte(n)
	return b
}

func decodeNanos(b []byte) int64 {
	return int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
		int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Simulated network conditions: artificial latency + jitter
// ═══════════════════════════════════════════════════════════════════════════════

// delayRelay simulates network delay by adding a fixed latency + jitter.
type delayRelay struct {
	pair      *relayPair
	baseDelay time.Duration
	jitter    time.Duration
	cancel    chan struct{}
}

func newDelayRelay(t testing.TB, baseDelay, jitter time.Duration, encrypted bool) *delayRelay {
	rp := newRelayPair(t, encrypted)
	return &delayRelay{pair: rp, baseDelay: baseDelay, jitter: jitter, cancel: make(chan struct{})}
}

func (dr *delayRelay) start(t testing.TB) {
	t.Helper()
	sinkTarget := dr.pair.sink.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 64*1024)
		for {
			select {
			case <-dr.cancel:
				return
			default:
			}
			_ = dr.pair.relayRecv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _, err := dr.pair.relayRecv.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			raw := buf[:n]

			// Simulate one-way network delay.
			delay := dr.baseDelay
			if dr.jitter > 0 {
				// Simple pseudo-jitter using the first payload byte.
				jitterRange := int64(dr.jitter)
				jitterNs := int64(raw[0]%128) * jitterRange / 128
				delay += time.Duration(jitterNs)
			}
			time.Sleep(delay)

			// Encode/decode pass.
			var payload []byte
			if dr.pair.ks.Enabled() {
				wire := EncodeDataEnc2ForKeyID(dr.pair.ks, dr.pair.ks.CurID, dr.pair.route, dr.pair.client, raw)
				_, _, p, _, ok := DecodeDataEnc2(dr.pair.ks, wire)
				if !ok {
					continue
				}
				payload = p
			} else {
				wire := EncodeData(dr.pair.route, dr.pair.client, raw)
				_, _, p, ok := DecodeData(wire)
				if !ok {
					continue
				}
				payload = p
			}
			_, _ = dr.pair.relaySend.WriteToUDP(payload, sinkTarget)
		}
	}()
}

func (dr *delayRelay) close() {
	close(dr.cancel)
	dr.pair.close()
}

func TestUDPRelayWithSimulatedLatency(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	scenarios := []struct {
		name    string
		delay   time.Duration
		jitter  time.Duration
	}{
		{"LAN_0ms", 0, 0},
		{"WAN_20ms", 20 * time.Millisecond, 5 * time.Millisecond},
		{"WAN_50ms", 50 * time.Millisecond, 10 * time.Millisecond},
		{"Bad_100ms", 100 * time.Millisecond, 30 * time.Millisecond},
	}

	t.Logf("\n%-20s %8s %8s %10s %10s %10s", "Scenario", "Sent", "Recv", "Loss%", "P50", "P99")
	t.Logf("%-20s %8s %8s %10s %10s %10s", "--------", "----", "----", "-----", "---", "---")

	for _, sc := range scenarios {
		dr := newDelayRelay(t, sc.delay, sc.jitter, true)
		dr.start(t)

		payload := make([]byte, 1400)
		const N = 500
		latencies := make([]time.Duration, 0, N)

		for i := 0; i < N; i++ {
			rand.Read(payload)
			copy(payload[:8], encodeNanos(time.Now().UnixNano()))
			_, _ = dr.pair.source.Write(payload)

			buf := make([]byte, 64*1024)
			_ = dr.pair.sink.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _, err := dr.pair.sink.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if n >= 8 {
				lat := time.Since(time.Unix(0, decodeNanos(buf[:8])))
				latencies = append(latencies, lat)
			}
		}

		dr.close()
		sent := N
		recv := len(latencies)
		loss := float64(sent-recv) / float64(sent) * 100

		p50Str, p99Str := "N/A", "N/A"
		if len(latencies) > 0 {
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			p50Str = latencies[len(latencies)*50/100].String()
			p99Str = latencies[len(latencies)*99/100].String()
		}

		t.Logf("%-20s %8d %8d %9.1f%% %10s %10s", sc.name, sent, recv, loss, p50Str, p99Str)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Burst test: simulates Sunshine keyframe bursts (many large packets at once)
// ═══════════════════════════════════════════════════════════════════════════════

func TestUDPRelayBurst(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	rp := newRelayPair(t, true)
	rp.startRelay(t)

	payload := make([]byte, 1400)
	rand.Read(payload)

	// Sunshine sends ~30 packets in rapid succession for a keyframe (~42KB).
	// Then ~800 packets/sec steady-state for P-frames.
	burstSizes := []int{10, 30, 60, 100}

	t.Logf("\n%-15s %8s %8s %10s", "BurstSize", "Sent", "Recv", "Loss%")
	t.Logf("%-15s %8s %8s %10s", "---------", "----", "----", "-----")

	for _, burst := range burstSizes {
		const rounds = 50
		var totalSent, totalRecv int64

		for r := 0; r < rounds; r++ {
			// Send burst
			for i := 0; i < burst; i++ {
				_, _ = rp.source.Write(payload)
				totalSent++
			}
			// Collect as many as we can in 50ms
			deadline := time.Now().Add(50 * time.Millisecond)
			buf := make([]byte, 64*1024)
			for time.Now().Before(deadline) {
				_ = rp.sink.SetReadDeadline(deadline)
				n, _, err := rp.sink.ReadFromUDP(buf)
				if err != nil {
					break
				}
				if n > 0 {
					totalRecv++
				}
			}
			// Small gap between bursts
			time.Sleep(10 * time.Millisecond)
		}

		loss := float64(totalSent-totalRecv) / float64(totalSent) * 100
		t.Logf("%-15d %8d %8d %9.1f%%", burst, totalSent, totalRecv, loss)
	}

	rp.close()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Bidirectional test: video downstream + input upstream simultaneously
// ═══════════════════════════════════════════════════════════════════════════════

func TestUDPRelayBidirectional(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// Video: Server→Client (1400B at ~800pps)
	videoRelay := newRelayPair(t, true)
	videoRelay.startRelay(t)

	// Input: Client→Server (32B at ~120pps) — separate relay
	inputRelay := newRelayPair(t, true)
	inputRelay.startRelay(t)

	const testDuration = 3 * time.Second
	deadline := time.Now().Add(testDuration)

	var videoSent, videoRecv, inputSent, inputRecv atomic.Int64
	var wg sync.WaitGroup

	// Video sender (800 pps)
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload := make([]byte, 1400)
		rand.Read(payload)
		ticker := time.NewTicker(1250 * time.Microsecond) // ~800 pps
		defer ticker.Stop()
		for range ticker.C {
			if time.Now().After(deadline) {
				return
			}
			_, _ = videoRelay.source.Write(payload)
			videoSent.Add(1)
		}
	}()

	// Video receiver
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for {
			_ = videoRelay.sink.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, _, err := videoRelay.sink.ReadFromUDP(buf)
			if err != nil {
				if time.Now().After(deadline.Add(1 * time.Second)) {
					return
				}
				continue
			}
			if n > 0 {
				videoRecv.Add(1)
			}
		}
	}()

	// Input sender (120 pps)
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload := make([]byte, 32)
		rand.Read(payload)
		ticker := time.NewTicker(8333 * time.Microsecond) // ~120 pps
		defer ticker.Stop()
		for range ticker.C {
			if time.Now().After(deadline) {
				return
			}
			_, _ = inputRelay.source.Write(payload)
			inputSent.Add(1)
		}
	}()

	// Input receiver
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		for {
			_ = inputRelay.sink.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, _, err := inputRelay.sink.ReadFromUDP(buf)
			if err != nil {
				if time.Now().After(deadline.Add(1 * time.Second)) {
					return
				}
				continue
			}
			if n > 0 {
				inputRecv.Add(1)
			}
		}
	}()

	time.Sleep(testDuration + 2*time.Second)
	videoRelay.close()
	inputRelay.close()
	wg.Wait()

	vs, vr := videoSent.Load(), videoRecv.Load()
	is, ir := inputSent.Load(), inputRecv.Load()
	vLoss := float64(vs-vr) / float64(vs) * 100
	iLoss := float64(is-ir) / float64(is) * 100

	t.Logf("\nBidirectional test (%v):", testDuration)
	t.Logf("  Video: sent=%d recv=%d loss=%.1f%% (%.1f Mbps)",
		vs, vr, vLoss, float64(vr)*1400*8/testDuration.Seconds()/1e6)
	t.Logf("  Input: sent=%d recv=%d loss=%.1f%% (%.1f Kbps)",
		is, ir, iLoss, float64(ir)*32*8/testDuration.Seconds()/1e3)

	if vLoss > 5 {
		t.Errorf("video loss %.1f%% too high (expected <5%%)", vLoss)
	}
	if iLoss > 1 {
		t.Errorf("input loss %.1f%% too high (expected <1%%)", iLoss)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Encode/decode hot-path benchmark over real sockets
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkUDPRelay_Encrypted(b *testing.B) {
	rp := newRelayPair(b, true)
	rp.startRelay(b)
	defer rp.close()

	payload := make([]byte, 1400)
	rand.Read(payload)
	b.SetBytes(1400)
	b.ReportAllocs()

	buf := make([]byte, 64*1024)
	for i := 0; i < b.N; i++ {
		_, _ = rp.source.Write(payload)
		_ = rp.sink.SetReadDeadline(time.Now().Add(1 * time.Second))
		rp.sink.ReadFromUDP(buf)
	}
}

func BenchmarkUDPRelay_Plaintext(b *testing.B) {
	rp := newRelayPair(b, false)
	rp.startRelay(b)
	defer rp.close()

	payload := make([]byte, 1400)
	rand.Read(payload)
	b.SetBytes(1400)
	b.ReportAllocs()

	buf := make([]byte, 64*1024)
	for i := 0; i < b.N; i++ {
		_, _ = rp.source.Write(payload)
		_ = rp.sink.SetReadDeadline(time.Now().Add(1 * time.Second))
		rp.sink.ReadFromUDP(buf)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Buffer pool benchmark
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkBufPool_GetPut(b *testing.B) {
	pool := sync.Pool{New: func() any {
		buf := make([]byte, 64*1024)
		return &buf
	}}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ptr := pool.Get().(*[]byte)
			pool.Put(ptr)
		}
	})
}

func BenchmarkBufPool_GetPutWithWork(b *testing.B) {
	// Simulates the real hot-path: get buf, read into it, copy, process, put back.
	pool := sync.Pool{New: func() any {
		buf := make([]byte, 64*1024)
		return &buf
	}}
	payload := make([]byte, 1400)
	rand.Read(payload)
	b.SetBytes(1400)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ptr := pool.Get().(*[]byte)
		buf := *ptr
		copy(buf[:1400], payload)
		// Simulate decode overhead with a dummy scan.
		_ = buf[0]
		_ = buf[1399]
		pool.Put(ptr)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Data integrity under concurrency
// ═══════════════════════════════════════════════════════════════════════════════

func TestEncodeDecodeDataIntegrityConcurrent(t *testing.T) {
	ks := mustKeySet(t, ModeAES256)
	const goroutines = 8
	const pktsPerGoroutine = 5000

	var wg sync.WaitGroup
	var failures atomic.Int64

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			route := fmt.Sprintf("route%d", id)
			client := fmt.Sprintf("10.0.0.%d:1234", id)
			payload := make([]byte, 1400)
			rand.Read(payload)

			for i := 0; i < pktsPerGoroutine; i++ {
				// Encode
				wire := EncodeDataEnc2ForKeyID(ks, ks.CurID, route, client, payload)
				// Must copy for decode (in-place decrypt)
				wireCopy := make([]byte, len(wire))
				copy(wireCopy, wire)

				r, c, p, _, ok := DecodeDataEnc2(ks, wireCopy)
				if !ok {
					failures.Add(1)
					continue
				}
				if r != route || c != client || !bytes.Equal(p, payload) {
					failures.Add(1)
				}
			}
		}(g)
	}

	wg.Wait()
	f := failures.Load()
	total := int64(goroutines * pktsPerGoroutine)
	t.Logf("Concurrent integrity: %d/%d OK (%.2f%% failure)",
		total-f, total, float64(f)/float64(total)*100)
	if f > 0 {
		t.Errorf("%d integrity failures", f)
	}
}
