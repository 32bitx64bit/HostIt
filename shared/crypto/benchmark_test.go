package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

// BenchmarkEncryptUDP measures the per-datagram AES-GCM cost for UDP payload
// encryption. Run with realistic sizes (small for game/DNS packets, large
// for full MTU). The result bounds the per-packet cost on acceptPublicUDP.
func BenchmarkEncryptUDP(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192, 32 * 1024}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			aead := mustAEAD(b, 32)
			plain := make([]byte, n)
			rand.Read(plain)
			out := make([]byte, 0, n+32)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := EncryptUDP(aead, out[:0], plain); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecryptUDP measures the inverse. DecryptUDP runs on every inbound
// datagram on acceptAgentUDP, so this cost is paid for every public packet
// received.
func BenchmarkDecryptUDP(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192, 32 * 1024}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			aead := mustAEAD(b, 32)
			plain := make([]byte, n)
			rand.Read(plain)
			ciphertext, err := EncryptUDP(aead, make([]byte, 0, n+32), plain)
			if err != nil {
				b.Fatal(err)
			}
			out := make([]byte, 0, n)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := DecryptUDP(aead, out[:0], ciphertext); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUDPCipherRoundTrip covers the encrypt+decrypt pair over a single
// datagram. This is the realistic cost on a public UDP packet that traverses
// the tunnel, and the result directly limits the tunnel's per-packet budget.
func BenchmarkUDPCipherRoundTrip(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			aead := mustAEAD(b, 32)
			plain := make([]byte, n)
			encBuf := make([]byte, 0, n+32)
			decBuf := make([]byte, 0, n)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ct, err := EncryptUDP(aead, encBuf[:0], plain)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := DecryptUDP(aead, decBuf[:0], ct); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func mustAEAD(b *testing.B, keyLen int) cipher.AEAD {
	b.Helper()
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	aead, err := NewUDPCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	return aead
}

// BenchmarkEncryptUDPNoncePool exercises the amortized getrandom() path.
// The first calls pay the syscall to fill the batch; subsequent calls
// borrow from the pool. Run at a small size so the 12-byte nonce copy
// is visible in the per-op time.
func BenchmarkEncryptUDPNoncePool(b *testing.B) {
	aead := mustAEAD(b, 32)
	plain := make([]byte, 64)
	rand.Read(plain)
	out := make([]byte, 0, 128)
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptUDP(aead, out[:0], plain); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptUDPNoncePoolConcurrent is the multi-goroutine view of
// the nonce pool. With many goroutines the pool's LIFO behavior means
// each goroutine tends to hold its own batch slice, so the amortized
// getrandom() rate stays low. This benchmark surfaces contention on the
// pool's internal lock.
func BenchmarkEncryptUDPNoncePoolConcurrent(b *testing.B) {
	aead := mustAEAD(b, 32)
	plain := make([]byte, 64)
	rand.Read(plain)
	b.SetBytes(int64(len(plain)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		out := make([]byte, 0, 128)
		for pb.Next() {
			if _, err := EncryptUDP(aead, out[:0], plain); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkStreamCipherEncrypt is the cached-metadata fast path. It
// skips the two cipher.AEAD interface dispatches that the standard
// EncryptUDP path performs on every packet, so the measured time is
// closer to the underlying Seal floor. Compare against
// BenchmarkEncryptUDP to see the per-call overhead the wrapper saves.
func BenchmarkStreamCipherEncrypt(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192, 32 * 1024}
	aead := mustAEAD(b, 32)
	cipher := NewStreamCipher(aead)
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			plain := make([]byte, n)
			rand.Read(plain)
			out := make([]byte, 0, n+64)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := cipher.Encrypt(out[:0], plain); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkStreamCipherDecrypt is the matching fast path for decrypt.
func BenchmarkStreamCipherDecrypt(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192, 32 * 1024}
	aead := mustAEAD(b, 32)
	cipher := NewStreamCipher(aead)
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			plain := make([]byte, n)
			ct, err := cipher.Encrypt(make([]byte, 0, n+64), plain)
			if err != nil {
				b.Fatal(err)
			}
			out := make([]byte, 0, n)
			b.SetBytes(int64(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := cipher.Decrypt(out[:0], ct); err != nil {
					b.Fatal(err)
				}
			}
		})
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
