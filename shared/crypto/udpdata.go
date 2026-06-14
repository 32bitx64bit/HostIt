package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
)

// UDP data-plane encryption uses per-session directional keys,
// deterministic counter nonces, and per-sender anti-replay windows.
const (
	UDPDirClientToServer = "hostit-udp-c2s"
	UDPDirServerToClient = "hostit-udp-s2c"

	udpNoncePrefixLen  = 4
	udpNonceCounterLen = 8
	udpNonceLen        = udpNoncePrefixLen + udpNonceCounterLen // == GCM nonce size

	// replayWindowBits is the anti-replay reorder tolerance.
	replayWindowBits  = 1024
	replayWindowWords = replayWindowBits / 64

	maxReplayPrefixes = 8
)

var (
	ErrUDPCiphertextShort = errors.New("udp ciphertext too short")
	ErrUDPReplay          = errors.New("udp packet replayed or too old")
)

func DeriveUDPSessionKey(baseKey, sessionID []byte, direction string) ([]byte, error) {
	if len(baseKey) == 0 {
		return nil, errors.New("empty base key")
	}
	return hkdf.Key(sha256.New, baseKey, sessionID, direction, len(baseKey))
}

// UDPEncryptor seals datagrams with deterministic nonces. Safe for concurrent use.
type UDPEncryptor struct {
	aead     cipher.AEAD
	overhead int
	prefix   [udpNoncePrefixLen]byte
	counter  atomic.Uint64
}

func NewUDPEncryptor(key []byte) (*UDPEncryptor, error) {
	aead, err := newGCM(key)
	if err != nil || aead == nil {
		return nil, err
	}
	e := &UDPEncryptor{aead: aead, overhead: aead.Overhead()}
	if _, err := io.ReadFull(rand.Reader, e.prefix[:]); err != nil {
		return nil, err
	}
	return e, nil
}

// Seal encrypts plaintext into dst, producing nonce || ciphertext+tag.
func (e *UDPEncryptor) Seal(dst, plaintext, aad []byte) ([]byte, error) {
	outLen := udpNonceLen + len(plaintext) + e.overhead
	if cap(dst) < outLen {
		dst = make([]byte, udpNonceLen, outLen)
	} else {
		dst = dst[:udpNonceLen]
	}
	copy(dst[:udpNoncePrefixLen], e.prefix[:])
	binary.BigEndian.PutUint64(dst[udpNoncePrefixLen:udpNonceLen], e.counter.Add(1))
	return e.aead.Seal(dst, dst[:udpNonceLen], plaintext, aad), nil
}

// replayState is a sliding-window replay filter.
type replayState struct {
	highest  uint64
	bits     [replayWindowWords]uint64
	lastUsed uint64
}

// accept reports whether ctr is fresh (>=1, within replayWindowBits of the
// highest seen, and not previously accepted), recording it if so. It uses an
// RFC 6479-style circular bitmap indexed by ctr mod the window size, so an
// in-order packet only clears+sets one bit instead of shifting the whole
// window. Counters reach here only after the AEAD tag is verified, so an
// attacker cannot drive the counter; forward jumps are bounded by real loss.
func (w *replayState) accept(ctr uint64) bool {
	if ctr == 0 {
		return false // counters start at 1
	}
	if ctr > w.highest {
		diff := ctr - w.highest
		if diff >= replayWindowBits {
			for i := range w.bits {
				w.bits[i] = 0
			}
		} else {
			// Positions newly slid into the window still hold bits from a
			// counter replayWindowBits ago; clear them before reuse.
			for i := w.highest + 1; i <= ctr; i++ {
				idx := i & (replayWindowBits - 1)
				w.bits[idx>>6] &^= uint64(1) << (idx & 63)
			}
		}
		w.highest = ctr
		idx := ctr & (replayWindowBits - 1)
		w.bits[idx>>6] |= uint64(1) << (idx & 63)
		return true
	}
	if w.highest-ctr >= replayWindowBits {
		return false // older than the window
	}
	idx := ctr & (replayWindowBits - 1)
	word, bit := idx>>6, idx&63
	mask := uint64(1) << bit
	if w.bits[word]&mask != 0 {
		return false // replayed
	}
	w.bits[word] |= mask
	return true
}

// UDPDecryptor opens datagrams with anti-replay enforcement.
// NOT safe for concurrent use.
type UDPDecryptor struct {
	aead     cipher.AEAD
	overhead int
	windows  map[uint32]*replayState
	useSeq   uint64
}

func NewUDPDecryptor(key []byte) (*UDPDecryptor, error) {
	aead, err := newGCM(key)
	if err != nil || aead == nil {
		return nil, err
	}
	return &UDPDecryptor{
		aead:     aead,
		overhead: aead.Overhead(),
		windows:  make(map[uint32]*replayState, 2),
	}, nil
}

// Open decrypts packet into dst. Replay/stale packets return ErrUDPReplay.
func (d *UDPDecryptor) Open(dst, packet, aad []byte) ([]byte, error) {
	if len(packet) < udpNonceLen+d.overhead {
		return nil, ErrUDPCiphertextShort
	}
	nonce, ciphertext := packet[:udpNonceLen], packet[udpNonceLen:]

	outLen := len(ciphertext) - d.overhead
	if cap(dst) < outLen {
		dst = make([]byte, 0, outLen)
	} else {
		dst = dst[:0]
	}
	plaintext, err := d.aead.Open(dst, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}

	prefix := binary.BigEndian.Uint32(nonce[:udpNoncePrefixLen])
	ctr := binary.BigEndian.Uint64(nonce[udpNoncePrefixLen:udpNonceLen])
	if !d.window(prefix).accept(ctr) {
		return nil, ErrUDPReplay
	}
	return plaintext, nil
}

func (d *UDPDecryptor) window(prefix uint32) *replayState {
	d.useSeq++
	if w, ok := d.windows[prefix]; ok {
		w.lastUsed = d.useSeq
		return w
	}
	if len(d.windows) >= maxReplayPrefixes {
		var oldestKey uint32
		oldest := uint64(1<<64 - 1)
		for k, w := range d.windows {
			if w.lastUsed < oldest {
				oldest = w.lastUsed
				oldestKey = k
			}
		}
		delete(d.windows, oldestKey)
	}
	w := &replayState{lastUsed: d.useSeq}
	d.windows[prefix] = w
	return w
}

// UDPSessionCrypto is the encrypt/decrypt pair for a UDP session.
type UDPSessionCrypto struct {
	Enc *UDPEncryptor
	Dec *UDPDecryptor
}

// NewUDPSessionCrypto builds the encryptor/decryptor for a session.
func NewUDPSessionCrypto(baseKey, sessionID []byte, encDir, decDir string) (*UDPSessionCrypto, error) {
	encKey, err := DeriveUDPSessionKey(baseKey, sessionID, encDir)
	if err != nil {
		return nil, err
	}
	decKey, err := DeriveUDPSessionKey(baseKey, sessionID, decDir)
	if err != nil {
		return nil, err
	}
	enc, err := NewUDPEncryptor(encKey)
	if err != nil {
		return nil, err
	}
	dec, err := NewUDPDecryptor(decKey)
	if err != nil {
		return nil, err
	}
	return &UDPSessionCrypto{Enc: enc, Dec: dec}, nil
}

// AppendUDPDataAAD appends length-prefixed route/client AAD.
func AppendUDPDataAAD(dst []byte, route, client string) []byte {
	dst = append(dst, byte(len(route)))
	dst = append(dst, route...)
	dst = append(dst, byte(len(client)))
	dst = append(dst, client...)
	return dst
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 {
		return nil, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
