package udpproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
)

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
	info := []byte("playit-prototype/udp/" + string(mode))
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

// EncodeRegEnc2 encrypts the token and includes the current key id.
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

// DecodeRegEnc2 verifies the token and returns the key id used.
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
	pt := encodeDataPayload(route, client, payload)
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	ct := aead.Seal(nil, nonce, pt, nil)
	b := make([]byte, 1+4+len(nonce)+len(ct))
	b[0] = MsgDataEnc2
	binary.BigEndian.PutUint32(b[1:5], keyID)
	copy(b[5:], nonce)
	copy(b[5+len(nonce):], ct)
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
	pt, err := aead.Open(nil, nonce, ct, nil)
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
	pt := encodeDataPayload(route, client, payload)
	b := make([]byte, 1+len(pt))
	b[0] = MsgData
	copy(b[1:], pt)
	return b
}

func DecodeData(b []byte) (route string, client string, payload []byte, ok bool) {
	if len(b) < 1+1+2 || b[0] != MsgData {
		return "", "", nil, false
	}
	route, client, payload, ok = decodeDataPayload(b[1:])
	return route, client, payload, ok
}
