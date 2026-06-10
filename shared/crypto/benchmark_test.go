package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

// BenchmarkEncryptUDP measures the per-datagram AES-GCM encryption cost.
// The result bounds the per-packet cost on acceptPublicUDP.
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

// BenchmarkDecryptUDP measures AES-GCM decryption, paid for every inbound
// datagram on acceptAgentUDP.
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

// BenchmarkUDPCipherRoundTrip covers encrypt+decrypt for a single datagram,
// the realistic cost for a public UDP packet traversing the tunnel.
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
// Run at a small size so the 12-byte nonce copy is visible.
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

// BenchmarkEncryptUDPNoncePoolConcurrent is the multi-goroutine view.
// Surfaces contention on the pool's internal lock.
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

// BenchmarkStreamCipherEncrypt is the cached-metadata fast path, skipping
// two cipher.AEAD interface dispatches per packet. Compare against
// BenchmarkEncryptUDP to measure wrapper overhead.
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
