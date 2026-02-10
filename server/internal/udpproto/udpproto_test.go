package udpproto

import (
	"bytes"
	"crypto/rand"
	"fmt"
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
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	ks, err := NewKeySet(mode, "test-token-secret-123", 1, salt, 0, nil)
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
	ks, err := NewKeySet(mode, "test-token-secret-123", 2, salt1, 1, salt2)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// ── Correctness tests ─────────────────────────────────────────────────────

func TestEncodeDecodeDataEnc2_AES256(t *testing.T) {
	ks := mustKeySet(t, ModeAES256)
	payload := make([]byte, 1400)
	rand.Read(payload)

	wire := EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "10.0.0.5:9000", payload)
	r, c, p, kid, ok := DecodeDataEnc2(ks, wire)
	if !ok {
		t.Fatal("decode failed")
	}
	if r != "stream" || c != "10.0.0.5:9000" || kid != ks.CurID {
		t.Fatalf("got route=%q client=%q keyID=%d", r, c, kid)
	}
	if !bytes.Equal(p, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestEncodeDecodeDataEnc2_AES128(t *testing.T) {
	ks := mustKeySet(t, ModeAES128)
	payload := []byte("hello AES-128")

	wire := EncodeDataEnc2ForKeyID(ks, ks.CurID, "audio", "192.168.1.5:4321", payload)
	r, c, p, _, ok := DecodeDataEnc2(ks, wire)
	if !ok {
		t.Fatal("decode failed")
	}
	if r != "audio" || c != "192.168.1.5:4321" {
		t.Fatalf("got route=%q client=%q", r, c)
	}
	if !bytes.Equal(p, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestEncodeDecodeDataEnc2_KeyRotation(t *testing.T) {
	ks := mustKeySetDual(t, ModeAES256)
	payload := []byte("key rotation test")

	// Encode with prev key — should decode with prev key.
	wire := EncodeDataEnc2ForKeyID(ks, ks.PrevID, "stream", "10.0.0.1:1234", payload)
	_, _, p, kid, ok := DecodeDataEnc2(ks, wire)
	if !ok {
		t.Fatal("decode with prev key failed")
	}
	if kid != ks.PrevID {
		t.Fatalf("expected keyID=%d, got %d", ks.PrevID, kid)
	}
	if !bytes.Equal(p, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestDecodeDataEnc2_WrongKey(t *testing.T) {
	ks1 := mustKeySet(t, ModeAES256)
	ks2 := mustKeySet(t, ModeAES256)

	wire := EncodeDataEnc2ForKeyID(ks1, ks1.CurID, "stream", "10.0.0.1:1234", []byte("secret"))
	// Force same key ID so aeadFor matches
	wire[1], wire[2], wire[3], wire[4] = 0, 0, 0, byte(ks2.CurID)
	_, _, _, _, ok := DecodeDataEnc2(ks2, wire)
	if ok {
		t.Fatal("should fail with wrong key")
	}
}

func TestEncodeDecodeData_Plaintext(t *testing.T) {
	payload := make([]byte, 1400)
	rand.Read(payload)

	wire := EncodeData("game", "192.168.1.100:5555", payload)
	r, c, p, ok := DecodeData(wire)
	if !ok {
		t.Fatal("decode failed")
	}
	if r != "game" || c != "192.168.1.100:5555" {
		t.Fatalf("got route=%q client=%q", r, c)
	}
	if !bytes.Equal(p, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestEncodeDecodeReg(t *testing.T) {
	wire := EncodeReg("my-token-xyz")
	tok, ok := DecodeReg(wire)
	if !ok || tok != "my-token-xyz" {
		t.Fatalf("got tok=%q ok=%v", tok, ok)
	}
}

func TestEncodeDecodeRegEnc2(t *testing.T) {
	ks := mustKeySet(t, ModeAES256)
	wire := EncodeRegEnc2(ks, "my-token-xyz")
	kid, ok := DecodeRegEnc2(ks, "my-token-xyz", wire)
	if !ok || kid != ks.CurID {
		t.Fatalf("got kid=%d ok=%v", kid, ok)
	}
	_, ok = DecodeRegEnc2(ks, "wrong-token", wire)
	if ok {
		t.Fatal("should reject wrong token")
	}
}

func TestNonceUniqueness(t *testing.T) {
	// Verify nonces are unique across calls.
	seen := make(map[[12]byte]bool)
	buf := make([]byte, 12)
	for i := 0; i < 100000; i++ {
		fillNonce(buf)
		var key [12]byte
		copy(key[:], buf)
		if seen[key] {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		seen[key] = true
	}
}

// ── Benchmarks ─────────────────────────────────────────────────────────────

func BenchmarkEncodeDataEnc2_AES256(b *testing.B) {
	ks := mustKeySet(b, ModeAES256)
	payload := make([]byte, 1400)
	rand.Read(payload)
	b.SetBytes(1400)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "10.0.0.5:9000", payload)
	}
}

func BenchmarkEncodeDataEnc2_AES128(b *testing.B) {
	ks := mustKeySet(b, ModeAES128)
	payload := make([]byte, 1400)
	rand.Read(payload)
	b.SetBytes(1400)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "10.0.0.5:9000", payload)
	}
}

func BenchmarkDecodeDataEnc2(b *testing.B) {
	ks := mustKeySet(b, ModeAES256)
	payload := make([]byte, 1400)
	rand.Read(payload)
	wire := EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "10.0.0.5:9000", payload)
	b.SetBytes(1400)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		wireCopy := make([]byte, len(wire))
		copy(wireCopy, wire)
		DecodeDataEnc2(ks, wireCopy)
	}
}

func BenchmarkEncodeData(b *testing.B) {
	payload := make([]byte, 1400)
	rand.Read(payload)
	b.SetBytes(1400)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		EncodeData("stream", "10.0.0.5:9000", payload)
	}
}

func BenchmarkDecodeData(b *testing.B) {
	payload := make([]byte, 1400)
	rand.Read(payload)
	wire := EncodeData("stream", "10.0.0.5:9000", payload)
	b.SetBytes(1400)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		DecodeData(wire)
	}
}

func BenchmarkFillNonce(b *testing.B) {
	buf := make([]byte, 12)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fillNonce(buf)
	}
}

func BenchmarkEncodeDataEnc2_Parallel(b *testing.B) {
	ks := mustKeySet(b, ModeAES256)
	payload := make([]byte, 1400)
	rand.Read(payload)
	b.SetBytes(1400)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "10.0.0.5:9000", payload)
		}
	})
}

func BenchmarkDecodeDataEnc2_Parallel(b *testing.B) {
	ks := mustKeySet(b, ModeAES256)
	payload := make([]byte, 1400)
	rand.Read(payload)
	wire := EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "10.0.0.5:9000", payload)
	b.SetBytes(1400)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			wireCopy := make([]byte, len(wire))
			copy(wireCopy, wire)
			DecodeDataEnc2(ks, wireCopy)
		}
	})
}

// ── Streaming throughput report ─────────────────────────────────────────────

func TestStreamingThroughputReport(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	type scenario struct {
		name    string
		mode    Mode
		pktSize int
	}
	scenarios := []scenario{
		{"Video_1080p60_AES256", ModeAES256, 1400},
		{"Video_1080p60_AES128", ModeAES128, 1400},
		{"Video_1080p60_Plain", ModeNone, 1400},
		{"Audio_Opus_AES256", ModeAES256, 480},
		{"Input_AES256", ModeAES256, 32},
	}

	t.Logf("\n%-30s %8s %8s %8s %10s", "Scenario", "Mode", "pps", "Mbps", "Encode µs")
	t.Logf("%-30s %8s %8s %8s %10s", "--------", "----", "---", "----", "---------")

	for _, sc := range scenarios {
		payload := make([]byte, sc.pktSize)
		rand.Read(payload)
		ks := KeySet{Mode: ModeNone}
		if sc.mode != ModeNone {
			ks = mustKeySet(t, sc.mode)
		}

		const iters = 500000
		start := time.Now()
		for i := 0; i < iters; i++ {
			if ks.Enabled() {
				EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "10.0.0.5:9000", payload)
			} else {
				EncodeData("stream", "10.0.0.5:9000", payload)
			}
		}
		elapsed := time.Since(start)
		pps := float64(iters) / elapsed.Seconds()
		mbps := pps * float64(sc.pktSize) * 8 / 1e6
		usPerPkt := elapsed.Seconds() / float64(iters) * 1e6
		modeStr := "plain"
		if ks.Enabled() {
			modeStr = "enc"
		}
		t.Logf("%-30s %8s %8d %8.1f %10.2f", sc.name, modeStr, int(pps), mbps, usPerPkt)
	}
}

// ── GC pressure report ──────────────────────────────────────────────────────

func TestGCPressure(t *testing.T) {
	ks := mustKeySet(t, ModeAES256)
	payload := make([]byte, 1400)
	rand.Read(payload)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	gcBefore := before.NumGC

	const N = 100000
	for i := 0; i < N; i++ {
		wire := EncodeDataEnc2ForKeyID(ks, ks.CurID, "stream", "10.0.0.5:9000", payload)
		wireCopy := make([]byte, len(wire))
		copy(wireCopy, wire)
		DecodeDataEnc2(ks, wireCopy)
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	allocs := after.Mallocs - before.Mallocs
	allocBytes := after.TotalAlloc - before.TotalAlloc
	gcCount := after.NumGC - gcBefore

	t.Logf("Per-packet: %.1f allocs, %d bytes, %d GC cycles over %d packets",
		float64(allocs)/float64(N), allocBytes/uint64(N), gcCount, N)
}

// ── Data integrity under concurrency ─────────────────────────────────────────

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
				wire := EncodeDataEnc2ForKeyID(ks, ks.CurID, route, client, payload)
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
