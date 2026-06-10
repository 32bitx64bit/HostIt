package crypto

import (
	"crypto/rand"
	"testing"
)

func mustSessionCrypto(b *testing.B) (*UDPEncryptor, *UDPDecryptor) {
	b.Helper()
	baseKey := make([]byte, 32)
	if _, err := rand.Read(baseKey); err != nil {
		b.Fatal(err)
	}
	sessionID, err := NewUDPSessionID()
	if err != nil {
		b.Fatal(err)
	}
	sc, err := NewUDPSessionCrypto(baseKey, sessionID[:], UDPDirClientToServer, UDPDirClientToServer)
	if err != nil {
		b.Fatal(err)
	}
	return sc.Enc, sc.Dec
}

var benchAAD = AppendUDPDataAAD(nil, "bench-route", "203.0.113.10:51820")

// BenchmarkUDPSeal measures the per-datagram seal cost (deterministic
// nonce + AES-GCM + AAD). The result bounds the per-packet cost on
// acceptPublicUDP. No RNG is touched per packet.
func BenchmarkUDPSeal(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192, 32 * 1024}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			enc, _ := mustSessionCrypto(b)
			plain := make([]byte, n)
			rand.Read(plain)
			out := make([]byte, 0, n+64)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := enc.Seal(out[:0], plain, benchAAD); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUDPOpen measures decryption plus the anti-replay window check,
// paid for every inbound datagram on acceptAgentUDP.
func BenchmarkUDPOpen(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192, 32 * 1024}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			enc, dec := mustSessionCrypto(b)
			plain := make([]byte, n)
			rand.Read(plain)
			// The replay window rejects duplicate counters, so a single
			// pre-sealed packet cannot be opened twice. Pre-seal a bounded
			// batch and reset the window when it wraps; the reset cost is
			// amortized to nothing.
			const batch = 1024
			packets := make([][]byte, batch)
			for i := range packets {
				ct, err := enc.Seal(nil, plain, benchAAD)
				if err != nil {
					b.Fatal(err)
				}
				packets[i] = ct
			}
			out := make([]byte, 0, n)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				j := i % batch
				if j == 0 && i > 0 {
					dec.windows = make(map[uint32]*replayState, 2)
				}
				if _, err := dec.Open(out[:0], packets[j], benchAAD); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUDPRoundTrip covers seal+open for a single datagram, the
// realistic cost for a public UDP packet traversing the tunnel.
func BenchmarkUDPRoundTrip(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			enc, dec := mustSessionCrypto(b)
			plain := make([]byte, n)
			encBuf := make([]byte, 0, n+64)
			decBuf := make([]byte, 0, n)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ct, err := enc.Seal(encBuf[:0], plain, benchAAD)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := dec.Open(decBuf[:0], ct, benchAAD); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUDPSealConcurrent is the multi-goroutine view of the shared
// encryptor (atomic counter contention).
func BenchmarkUDPSealConcurrent(b *testing.B) {
	enc, _ := mustSessionCrypto(b)
	plain := make([]byte, 64)
	rand.Read(plain)
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		out := make([]byte, 0, 128)
		for pb.Next() {
			if _, err := enc.Seal(out[:0], plain, benchAAD); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkReplayWindowAccept isolates the sliding-window bookkeeping.
func BenchmarkReplayWindowAccept(b *testing.B) {
	var w replayState
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !w.accept(uint64(i + 1)) {
			b.Fatal("fresh counter rejected")
		}
	}
}

func payloadName(n int) string {
	if n >= 1024 {
		return itoa(n/1024) + "KB"
	}
	return itoa(n) + "B"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
