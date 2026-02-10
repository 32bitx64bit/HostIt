package udpproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
)

// Counter-based nonce generation — avoids crypto/rand.Read syscall per packet.
// The nonce is 12 bytes: 4-byte random prefix (set once at init) + 8-byte atomic counter.
// This guarantees uniqueness without any syscall on the hot path.
var (
	noncePrefix  [4]byte
	nonceCounter atomic.Uint64
)

func init() {
	_, _ = rand.Read(noncePrefix[:])
}

func fillNonce(dst []byte) {
	// dst must be at least 12 bytes (standard AES-GCM nonce size).
	copy(dst[:4], noncePrefix[:])
	binary.LittleEndian.PutUint64(dst[4:12], nonceCounter.Add(1))
}

// Pooled plaintext buffer to avoid per-packet allocation in encrypt path.
var ptPool = sync.Pool{New: func() any {
	b := make([]byte, 2048)
	return &b
}}

const (
	MsgReg      byte = 1
	MsgData     byte = 2
	MsgRegEnc   byte = 3 // legacy (unused)
	MsgDataEnc  byte = 4 // legacy (unused)
	MsgRegEnc2  byte = 5
	MsgDataEnc2 byte = 6
)

type Mode string

const (
	ModeNone   Mode = "none"
	ModeAES128 Mode = "aes128"
	ModeAES256 Mode = "aes256"
)

func NormalizeMode(s string) Mode {
	m := Mode(strings.ToLower(strings.TrimSpace(s)))
	switch m {
	case ModeNone, ModeAES128, ModeAES256:
		return m
	case "":
		return ModeAES256
	default:
		return ModeAES256
	}
}

type KeySet struct {
	Mode   Mode
	CurID  uint32
	Cur    cipher.AEAD
	PrevID uint32
	Prev   cipher.AEAD
}

func (ks KeySet) Enabled() bool {
	return ks.Mode == ModeAES128 || ks.Mode == ModeAES256
}

func NewKeySet(mode Mode, token string, curID uint32, curSalt []byte, prevID uint32, prevSalt []byte) (KeySet, error) {
	mode = NormalizeMode(string(mode))
	if mode == ModeNone {
		return KeySet{Mode: ModeNone}, nil
	}
	if strings.TrimSpace(token) == "" {
		return KeySet{}, errors.New("missing token")
	}
	cur, err := newAEAD(mode, token, curSalt)
	if err != nil {
		return KeySet{}, err
	}
	ks := KeySet{Mode: mode, CurID: curID, Cur: cur}
	if prevID != 0 && len(prevSalt) > 0 {
		if p, err := newAEAD(mode, token, prevSalt); err == nil {
			ks.PrevID = prevID
			ks.Prev = p
		}
	}
	return ks, nil
}

func (ks KeySet) aeadFor(id uint32) (cipher.AEAD, bool) {
	if ks.Cur != nil && id == ks.CurID {
		return ks.Cur, true
	}
	if ks.Prev != nil && id == ks.PrevID {
		return ks.Prev, true
	}
	return nil, false
}

func newAEAD(mode Mode, token string, salt []byte) (cipher.AEAD, error) {
	keyLen := 32
	if mode == ModeAES128 {
		keyLen = 16
	}
	if len(salt) == 0 {
		return nil, errors.New("missing salt")
	}
	info := []byte("hostit/udp/" + string(mode))
	rk := hkdf.New(sha256.New, []byte(token), salt, info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(rk, key); err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func EncodeRegEnc2(ks KeySet, token string) []byte {
	if !ks.Enabled() || ks.Cur == nil {
		return EncodeReg(token)
	}
	nonce := make([]byte, ks.Cur.NonceSize())
	_, _ = rand.Read(nonce)
	ct := ks.Cur.Seal(nil, nonce, []byte(token), nil)
	b := make([]byte, 1+4+len(nonce)+len(ct))
	b[0] = MsgRegEnc2
	binary.BigEndian.PutUint32(b[1:5], ks.CurID)
	copy(b[5:], nonce)
	copy(b[5+len(nonce):], ct)
	return b
}

func DecodeRegEnc2(ks KeySet, expectedToken string, b []byte) (keyID uint32, ok bool) {
	if len(b) < 1+4 || b[0] != MsgRegEnc2 {
		return 0, false
	}
	keyID = binary.BigEndian.Uint32(b[1:5])
	aead, ok := ks.aeadFor(keyID)
	if !ok {
		return 0, false
	}
	ns := aead.NonceSize()
	if len(b) < 1+4+ns+aead.Overhead() {
		return 0, false
	}
	nonce := b[5 : 5+ns]
	ct := b[5+ns:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return 0, false
	}
	if string(pt) != expectedToken {
		return 0, false
	}
	return keyID, true
}

func EncodeDataEnc2ForKeyID(ks KeySet, keyID uint32, route string, client string, payload []byte) []byte {
	if !ks.Enabled() {
		return EncodeData(route, client, payload)
	}
	aead, ok := ks.aeadFor(keyID)
	if !ok {
		aead = ks.Cur
		keyID = ks.CurID
		if aead == nil {
			return EncodeData(route, client, payload)
		}
	}

	// Build plaintext in a pooled buffer to avoid per-packet allocation.
	rb := route
	if len(rb) > 255 {
		rb = rb[:255]
	}
	cb := client
	if len(cb) > 65535 {
		cb = cb[:65535]
	}
	ptLen := 1 + len(rb) + 2 + len(cb) + len(payload)
	ptBufPtr := ptPool.Get().(*[]byte)
	ptBuf := *ptBufPtr
	if cap(ptBuf) < ptLen {
		ptBuf = make([]byte, ptLen)
	} else {
		ptBuf = ptBuf[:ptLen]
	}
	ptBuf[0] = byte(len(rb))
	o := 1
	copy(ptBuf[o:], rb)
	o += len(rb)
	binary.BigEndian.PutUint16(ptBuf[o:o+2], uint16(len(cb)))
	o += 2
	copy(ptBuf[o:], cb)
	o += len(cb)
	copy(ptBuf[o:], payload)

	// Single output allocation: header(5) + nonce(12) + ciphertext(ptLen + overhead).
	ns := aead.NonceSize()
	total := 1 + 4 + ns + ptLen + aead.Overhead()
	b := make([]byte, total)
	b[0] = MsgDataEnc2
	binary.BigEndian.PutUint32(b[1:5], keyID)
	nonce := b[5 : 5+ns]
	fillNonce(nonce)
	aead.Seal(b[5+ns:5+ns:total], nonce, ptBuf, nil)

	// Return plaintext buffer to pool.
	*ptBufPtr = ptBuf
	ptPool.Put(ptBufPtr)

	return b
}

func DecodeDataEnc2(ks KeySet, b []byte) (route string, client string, payload []byte, keyID uint32, ok bool) {
	if len(b) < 1+4 || b[0] != MsgDataEnc2 {
		return "", "", nil, 0, false
	}
	keyID = binary.BigEndian.Uint32(b[1:5])
	aead, ok := ks.aeadFor(keyID)
	if !ok {
		return "", "", nil, 0, false
	}
	ns := aead.NonceSize()
	if len(b) < 1+4+ns+aead.Overhead() {
		return "", "", nil, 0, false
	}
	nonce := b[5 : 5+ns]
	ct := b[5+ns:]
	// Decrypt in-place: reuse the ciphertext slice for plaintext output.
	pt, err := aead.Open(ct[:0], nonce, ct, nil)
	if err != nil {
		return "", "", nil, 0, false
	}
	route, client, payload, ok = decodeDataPayload(pt)
	return route, client, payload, keyID, ok
}

// Legacy chacha20poly1305-based helpers were removed in favor of AES-GCM modes.

func encodeDataPayload(route string, client string, payload []byte) []byte {
	rb := []byte(route)
	cb := []byte(client)
	if len(rb) > 255 {
		rb = rb[:255]
	}
	if len(cb) > 65535 {
		cb = cb[:65535]
	}
	b := make([]byte, 1+len(rb)+2+len(cb)+len(payload))
	b[0] = byte(len(rb))
	o := 1
	copy(b[o:], rb)
	o += len(rb)
	binary.BigEndian.PutUint16(b[o:o+2], uint16(len(cb)))
	o += 2
	copy(b[o:], cb)
	o += len(cb)
	copy(b[o:], payload)
	return b
}

func decodeDataPayload(b []byte) (route string, client string, payload []byte, ok bool) {
	if len(b) < 1+2 {
		return "", "", nil, false
	}
	rn := int(b[0])
	o := 1
	if rn < 0 || len(b) < o+rn+2 {
		return "", "", nil, false
	}
	route = string(b[o : o+rn])
	o += rn
	cn := int(binary.BigEndian.Uint16(b[o : o+2]))
	o += 2
	if cn < 0 || len(b) < o+cn {
		return "", "", nil, false
	}
	client = string(b[o : o+cn])
	o += cn
	payload = b[o:]
	return route, client, payload, true
}

func EncodeReg(token string) []byte {
	b := make([]byte, 1+2+len(token))
	b[0] = MsgReg
	binary.BigEndian.PutUint16(b[1:3], uint16(len(token)))
	copy(b[3:], token)
	return b
}

func DecodeReg(b []byte) (token string, ok bool) {
	if len(b) < 3 || b[0] != MsgReg {
		return "", false
	}
	n := int(binary.BigEndian.Uint16(b[1:3]))
	if n < 0 || len(b) != 3+n {
		return "", false
	}
	return string(b[3:]), true
}

func EncodeData(route string, client string, payload []byte) []byte {
	// Single-allocation version: write type byte + payload into one buffer.
	rb := route
	if len(rb) > 255 {
		rb = rb[:255]
	}
	cb := client
	if len(cb) > 65535 {
		cb = cb[:65535]
	}
	total := 1 + 1 + len(rb) + 2 + len(cb) + len(payload)
	b := make([]byte, total)
	b[0] = MsgData
	b[1] = byte(len(rb))
	o := 2
	copy(b[o:], rb)
	o += len(rb)
	binary.BigEndian.PutUint16(b[o:o+2], uint16(len(cb)))
	o += 2
	copy(b[o:], cb)
	o += len(cb)
	copy(b[o:], payload)
	return b
}

func DecodeData(b []byte) (route string, client string, payload []byte, ok bool) {
	if len(b) < 1+1+2 || b[0] != MsgData {
		return "", "", nil, false
	}
	route, client, payload, ok = decodeDataPayload(b[1:])
	return route, client, payload, ok
}
