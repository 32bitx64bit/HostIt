package udpproto

import (
	"bytes"
	"crypto/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func mustKeySet(t testing.TB, mode Mode) KeySet {
	t.Helper()
	salt := make([]byte, 16)
	rand.Read(salt)
	ks, err := NewKeySet(mode, "test-token-1234", 1, salt, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func mustKeySetDual(t testing.TB, mode Mode) KeySet {
	t.Helper()
	salt1 := make([]byte, 16)
	salt2 := make([]byte, 16)
	rand.Read(salt1)
	rand.Read(salt2)
	ks, err := NewKeySet(mode, "test-token-1234", 2, salt1, 1, salt2)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func randomPayload(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// ── Correctness tests ────────────────────────────────────────────────────────

func TestEncodeDecodeData(t *testing.T) {
	cases := []struct {
		route, client string
		payloadLen    int
	}{
		{"stream", "192.168.1.5:47821", 0},
		{"stream", "192.168.1.5:47821", 1},
		{"stream", "192.168.1.5:47821", 1400},
		{"a", "b", 65535},
		{"game-route-name", "[::1]:12345", 100},
	}
	for _, tc := range cases {
		payload := randomPayload(tc.payloadLen)
		encoded := EncodeData(tc.route, tc.client, payload)

		r, c, p, ok := DecodeData(encoded)
		if !ok {
			t.Fatalf("DecodeData failed for route=%q client=%q len=%d", tc.route, tc.client, tc.payloadLen)
		}
		if r != tc.route || c != tc.client {
			t.Fatalf("got route=%q client=%q, want %q %q", r, c, tc.route, tc.client)
		}
		if !bytes.Equal(p, payload) {
			t.Fatalf("payload mismatch (len got=%d want=%d)", len(p), len(payload))
		}
	}
}

func TestEncodeDecodeDataEnc2_AES256(t *testing.T) {
	ks := mustKeySet(t, ModeAES256)
	payload := randomPayload(1400)

	encoded := EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "10.0.0.1:9999", payload)
	if encoded[0] != MsgDataEnc2 {
		t.Fatalf("expected MsgDataEnc2 type byte, got %d", encoded[0])
	}

	r, c, p, kid, ok := DecodeDataEnc2(ks, encoded)
	if !ok {
		t.Fatal("DecodeDataEnc2 failed")
	}
	if r != "stream" || c != "10.0.0.1:9999" {
		t.Fatalf("got route=%q client=%q", r, c)
	}
	if kid != ks.CurID {
		t.Fatalf("got keyID=%d, want %d", kid, ks.CurID)
	}
	if !bytes.Equal(p, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestEncodeDecodeDataEnc2_AES128(t *testing.T) {
	ks := mustKeySet(t, ModeAES128)
	payload := randomPayload(500)

	encoded := EncodeDataEnc2ForKeyID(ks, ks.CurID, "audio", "10.0.0.2:1234", payload)
	r, c, p, _, ok := DecodeDataEnc2(ks, encoded)
	if !ok {
		t.Fatal("decode failed")
	}
	if r != "audio" || c != "10.0.0.2:1234" || !bytes.Equal(p, payload) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestEncodeDecodeDataEnc2_KeyRotation(t *testing.T) {
	ks := mustKeySetDual(t, ModeAES256)

	payload := randomPayload(100)

	// Encode with current key
	enc1 := EncodeDataEnc2ForKeyID(ks, ks.CurID, "r", "c", payload)
	// Encode with previous key
	enc2 := EncodeDataEnc2ForKeyID(ks, ks.PrevID, "r", "c", payload)

	// Both should decode
	_, _, p1, k1, ok1 := DecodeDataEnc2(ks, enc1)
	_, _, p2, k2, ok2 := DecodeDataEnc2(ks, enc2)
	if !ok1 || !ok2 {
		t.Fatal("decode failed for one of the keys")
	}
	if k1 != ks.CurID || k2 != ks.PrevID {
		t.Fatalf("keyIDs: got %d,%d want %d,%d", k1, k2, ks.CurID, ks.PrevID)
	}
	if !bytes.Equal(p1, payload) || !bytes.Equal(p2, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestDecodeDataEnc2_WrongKey(t *testing.T) {
	ks1 := mustKeySet(t, ModeAES256)
	ks2 := mustKeySet(t, ModeAES256) // different salt → different key
	payload := randomPayload(100)

	encoded := EncodeDataEnc2ForKeyID(ks1, ks1.CurID, "r", "c", payload)
	_, _, _, _, ok := DecodeDataEnc2(ks2, encoded)
	if ok {
		t.Fatal("expected decode to fail with wrong key")
	}
}

func TestDecodeDataEnc2_Tampered(t *testing.T) {
	ks := mustKeySet(t, ModeAES256)
	payload := randomPayload(100)

	encoded := EncodeDataEnc2ForKeyID(ks, ks.CurID, "r", "c", payload)
	// Flip a byte in the ciphertext
	encoded[len(encoded)-5] ^= 0xFF
	_, _, _, _, ok := DecodeDataEnc2(ks, encoded)
	if ok {
		t.Fatal("expected decode to fail with tampered data")
	}
}

func TestEncodeDecodeReg(t *testing.T) {
	token := "my-secret-token-12345"
	encoded := EncodeReg(token)
	got, ok := DecodeReg(encoded)
	if !ok || got != token {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestEncodeDecodeRegEnc2(t *testing.T) {
	ks := mustKeySet(t, ModeAES256)
	token := "my-secret-token-12345"

	encoded := EncodeRegEnc2(ks, token)
	kid, ok := DecodeRegEnc2(ks, token, encoded)
	if !ok {
		t.Fatal("decode failed")
	}
	if kid != ks.CurID {
		t.Fatalf("keyID=%d want %d", kid, ks.CurID)
	}
}

func TestDecodeData_EmptyAndMalformed(t *testing.T) {
	tests := [][]byte{
		nil,
		{},
		{MsgData},                    // too short
		{MsgData, 0},                 // missing client len
		{0xFF, 5, 'h', 'e', 'l', 'l', 'o', 0, 5}, // wrong type byte
	}
	for i, b := range tests {
		_, _, _, ok := DecodeData(b)
		if ok {
			t.Fatalf("test %d: expected decode failure", i)
		}
	}
}

func TestNonceUniqueness(t *testing.T) {
	// Verify fillNonce produces unique nonces across goroutines.
	const count = 10000
	nonces := make(chan [12]byte, count)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < count/8; j++ {
				var n [12]byte
				fillNonce(n[:])
				nonces <- n
			}
		}()
	}
	wg.Wait()
	close(nonces)

	seen := make(map[[12]byte]bool, count)
	for n := range nonces {
		if seen[n] {
			t.Fatal("duplicate nonce detected")
		}
		seen[n] = true
	}
}

// ── Overhead measurement ─────────────────────────────────────────────────────

func TestTunnelOverheadBytes(t *testing.T) {
	ks := mustKeySet(t, ModeAES256)
	route := "stream"
	client := "192.168.1.100:47821"

	payloads := []int{100, 500, 1000, 1200, 1400}
	for _, size := range payloads {
		payload := randomPayload(size)
		plain := EncodeData(route, client, payload)
		enc := EncodeDataEnc2ForKeyID(ks, ks.CurID, route, client, payload)

		plainOH := len(plain) - size
		encOH := len(enc) - size

		t.Logf("payload=%4d  plaintext_wire=%4d (+%2d OH)  encrypted_wire=%4d (+%2d OH)",
			size, len(plain), plainOH, len(enc), encOH)

		// Encrypted should always be at least 33 bytes more (nonce=12 + tag=16 + keyID=4 + type=1)
		if encOH < 33 {
			t.Fatalf("encrypted overhead %d is too low", encOH)
		}
	}
}

// ── Benchmarks ───────────────────────────────────────────────────────────────

// Typical Sunshine/Moonlight packet sizes for game streaming:
//   Video:  1200–1400 bytes (H.265 NAL units, pre-fragmented)
//   Audio:  200–960 bytes (Opus frames)
//   Input:  20–50 bytes (mouse/keyboard/controller)
//   Control: 50–200 bytes (codec negotiation, keepalive)

var benchPayloadSizes = []struct {
	name string
	size int
}{
	{"Input_32B", 32},
	{"Audio_480B", 480},
	{"Video_1200B", 1200},
	{"Video_1400B", 1400},
	{"ChunkMax_8KB", 8192},
}

func BenchmarkEncodeData(b *testing.B) {
	for _, tc := range benchPayloadSizes {
		payload := randomPayload(tc.size)
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = EncodeData("stream", "192.168.1.5:47821", payload)
			}
		})
	}
}

func BenchmarkDecodeData(b *testing.B) {
	for _, tc := range benchPayloadSizes {
		payload := randomPayload(tc.size)
		encoded := EncodeData("stream", "192.168.1.5:47821", payload)
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, _, _ = DecodeData(encoded)
			}
		})
	}
}

func BenchmarkEncodeDataEnc2_AES256(b *testing.B) {
	ks := mustKeySet(b, ModeAES256)
	for _, tc := range benchPayloadSizes {
		payload := randomPayload(tc.size)
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "192.168.1.5:47821", payload)
			}
		})
	}
}

func BenchmarkEncodeDataEnc2_AES128(b *testing.B) {
	ks := mustKeySet(b, ModeAES128)
	for _, tc := range benchPayloadSizes {
		payload := randomPayload(tc.size)
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "192.168.1.5:47821", payload)
			}
		})
	}
}

func BenchmarkDecodeDataEnc2(b *testing.B) {
	ks := mustKeySet(b, ModeAES256)
	for _, tc := range benchPayloadSizes {
		payload := randomPayload(tc.size)
		// Pre-encode many packets (each has unique nonce, can't reuse).
		const batchSize = 8192
		packets := make([][]byte, batchSize)
		for i := range packets {
			packets[i] = EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "192.168.1.5:47821", payload)
		}
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(tc.size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Copy packet since in-place decrypt mutates:
				pkt := make([]byte, len(packets[i%batchSize]))
				copy(pkt, packets[i%batchSize])
				_, _, _, _, _ = DecodeDataEnc2(ks, pkt)
			}
		})
	}
}

func BenchmarkFillNonce(b *testing.B) {
	var buf [12]byte
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fillNonce(buf[:])
	}
}

// BenchmarkEncodeDataEnc2_Parallel measures throughput under goroutine contention.
// This reflects the real-world server scenario: multiple worker goroutines
// encoding packets concurrently.
func BenchmarkEncodeDataEnc2_Parallel(b *testing.B) {
	ks := mustKeySet(b, ModeAES256)
	payload := randomPayload(1400)
	b.SetBytes(1400)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "192.168.1.5:47821", payload)
		}
	})
}

func BenchmarkDecodeDataEnc2_Parallel(b *testing.B) {
	ks := mustKeySet(b, ModeAES256)
	payload := randomPayload(1400)
	const batchSize = 16384
	packets := make([][]byte, batchSize)
	for i := range packets {
		packets[i] = EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "192.168.1.5:47821", payload)
	}
	b.SetBytes(1400)
	b.ReportAllocs()
	var idx atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := idx.Add(1) % batchSize
			pkt := make([]byte, len(packets[i]))
			copy(pkt, packets[i])
			_, _, _, _, _ = DecodeDataEnc2(ks, pkt)
		}
	})
}

// ── Streaming throughput simulation ──────────────────────────────────────────

func TestStreamingThroughputReport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping throughput report in short mode")
	}

	ks256 := mustKeySet(t, ModeAES256)
	ks128 := mustKeySet(t, ModeAES128)

	// Sunshine sends ~800 video packets/sec at 1080p 60fps (~9 Mbps).
	// Audio is ~50 packets/sec at ~480 bytes.
	// Input is ~120 packets/sec at ~32 bytes (from client to server — opposite direction).
	type scenario struct {
		name    string
		mode    string
		ks      KeySet
		pktSize int
		pps     int // target packets per second
	}
	scenarios := []scenario{
		{"Video_1080p60_AES256", "enc", ks256, 1400, 800},
		{"Video_1080p60_AES128", "enc", ks128, 1400, 800},
		{"Video_1080p60_Plain", "plain", KeySet{}, 1400, 800},
		{"Audio_Opus_AES256", "enc", ks256, 480, 50},
		{"Input_AES256", "enc", ks256, 32, 120},
	}

	t.Logf("\n%-30s %8s %10s %10s %10s", "Scenario", "Mode", "pps", "Mbps", "Encode µs")
	t.Logf("%-30s %8s %10s %10s %10s", "--------", "----", "---", "----", "---------")

	for _, sc := range scenarios {
		payload := randomPayload(sc.pktSize)
		const samples = 50000
		start := time.Now()
		for i := 0; i < samples; i++ {
			if sc.mode == "enc" {
				_ = EncodeDataEnc2ForKeyID(sc.ks, sc.ks.CurID, "stream", "192.168.1.5:47821", payload)
			} else {
				_ = EncodeData("stream", "192.168.1.5:47821", payload)
			}
		}
		elapsed := time.Since(start)
		encodeUs := float64(elapsed.Microseconds()) / float64(samples)
		achievablePPS := 1e6 / encodeUs
		mbps := achievablePPS * float64(sc.pktSize) * 8 / 1e6

		t.Logf("%-30s %8s %10.0f %10.1f %10.2f", sc.name, sc.mode, achievablePPS, mbps, encodeUs)

		if achievablePPS < float64(sc.pps) {
			t.Errorf("%s: achievable PPS %.0f < target %d", sc.name, achievablePPS, sc.pps)
		}
	}
}

// ── Roundtrip simulation (encode → network copy → decode) ────────────────────

func TestUDPRoundtripSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	ks := mustKeySet(t, ModeAES256)
	route := "stream"
	client := "192.168.1.100:47821"
	payload := randomPayload(1400)

	// Simulate the full pipeline:
	//   Sunshine → Agent EncodeEnc2 → (UDP) → Server DecodeEnc2 →
	//   Server EncodeData → (UDP socket) → Client DecodeData
	//
	// Measure total processing time for 10K packets (both directions).
	const N = 50000
	start := time.Now()
	for i := 0; i < N; i++ {
		// Agent → Server (encrypted)
		wire := EncodeDataEnc2ForKeyID(ks, ks.CurID, route, client, payload)
		r, c, p, _, ok := DecodeDataEnc2(ks, wire)
		if !ok {
			t.Fatal("decode agent→server failed")
		}
		// Server → Client (re-encode for public side — plaintext in this sim)
		wire2 := EncodeData(r, c, p)
		_, _, _, ok = DecodeData(wire2)
		if !ok {
			t.Fatal("decode server→public failed")
		}
	}
	elapsed := time.Since(start)

	pps := float64(N) / elapsed.Seconds()
	usPerPkt := float64(elapsed.Microseconds()) / float64(N)
	mbps := pps * 1400 * 8 / 1e6

	t.Logf("Full roundtrip (encode+decode both legs): %.0f pps, %.1f Mbps, %.2f µs/pkt", pps, mbps, usPerPkt)

	// At 1080p60, we need ~800 pps. This should easily exceed that.
	if pps < 5000 {
		t.Errorf("roundtrip too slow: %.0f pps (need ≥5000)", pps)
	}
}

// ── GC pressure test ─────────────────────────────────────────────────────────

func TestGCPressure(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	ks := mustKeySet(t, ModeAES256)
	payload := randomPayload(1400)

	// Force a GC to get a clean baseline.
	runtime.GC()
	var mBefore, mAfter runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	const N = 100000
	for i := 0; i < N; i++ {
		wire := EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "192.168.1.5:47821", payload)
		pkt := make([]byte, len(wire))
		copy(pkt, wire)
		_, _, _, _, _ = DecodeDataEnc2(ks, pkt)
	}

	runtime.ReadMemStats(&mAfter)
	allocsPerPkt := float64(mAfter.Mallocs-mBefore.Mallocs) / float64(N)
	bytesPerPkt := float64(mAfter.TotalAlloc-mBefore.TotalAlloc) / float64(N)
	gcPauses := mAfter.NumGC - mBefore.NumGC

	t.Logf("Per-packet: %.1f allocs, %.0f bytes, %d GC cycles over %d packets",
		allocsPerPkt, bytesPerPkt, gcPauses, N)

	// We expect ~3 allocs per encode+decode cycle:
	//   1: output buffer in Encode
	//   1: copy for decode test
	//   2: string(route) + string(client) in decode
	// Total: ~4. Flag if we see significantly more.
	if allocsPerPkt > 8 {
		t.Errorf("too many allocations per packet: %.1f (expected ≤8)", allocsPerPkt)
	}
}
