package crypto

import (
	"crypto/rand"
	"testing"
)

func sessionCryptoKeyLen(b *testing.B, keyLen int) (*UDPEncryptor, *UDPDecryptor) {
	b.Helper()
	baseKey := make([]byte, keyLen)
	rand.Read(baseKey)
	sid, err := NewUDPSessionID()
	if err != nil {
		b.Fatal(err)
	}
	sc, err := NewUDPSessionCrypto(baseKey, sid[:], UDPDirClientToServer, UDPDirServerToClient)
	if err != nil {
		b.Fatal(err)
	}
	return sc.Enc, sc.Dec
}

// BenchmarkAESKeySizeSeal compares AES-128 vs AES-256 GCM seal at a typical
// game-packet size, isolating the cost of the extra AES-256 rounds.
func BenchmarkAESKeySizeSeal(b *testing.B) {
	for _, kl := range []int{16, 32} {
		name := "AES128"
		if kl == 32 {
			name = "AES256"
		}
		b.Run(name, func(b *testing.B) {
			enc, _ := sessionCryptoKeyLen(b, kl)
			pt := make([]byte, 512)
			dst := make([]byte, 0, 4096)
			b.SetBytes(512)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := enc.Seal(dst[:0], pt, benchAAD); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkReplayWindowLookup measures the per-packet cost of resolving the
// replay window by nonce prefix (the map lookup inside Open), versus the
// hot-prefix fast path that the optimization adds.
func BenchmarkReplayWindowLookup(b *testing.B) {
	_, dec := sessionCryptoKeyLen(b, 32)
	const prefix = uint32(0x01020304)
	b.Run("MapLookup", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = dec.window(prefix)
		}
	})
}
