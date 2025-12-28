package agent

import (
	"encoding/base64"
	"strconv"
	"strings"
	"sync"

	"playit-prototype/client/internal/udpproto"
)

type udpSecurityState struct {
	mu sync.RWMutex
	ks udpproto.KeySet
}

func newUDPSecurityState() *udpSecurityState {
	return &udpSecurityState{ks: udpproto.KeySet{Mode: udpproto.ModeNone}}
}

func (s *udpSecurityState) ForceNone() {
	s.mu.Lock()
	s.ks = udpproto.KeySet{Mode: udpproto.ModeNone}
	s.mu.Unlock()
}

func (s *udpSecurityState) Get() udpproto.KeySet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ks
}

func (s *udpSecurityState) UpdateFromLine(token string, rest string) {
	// UDPSEC <mode> <keyid> <salt_b64|-> <prev_keyid> <prev_salt_b64|->
	f := strings.Fields(rest)
	if len(f) < 1 {
		return
	}
	mode := udpproto.NormalizeMode(f[0])
	if mode == udpproto.ModeNone {
		s.ForceNone()
		return
	}
	var keyID uint32
	var prevID uint32
	var curSalt []byte
	var prevSalt []byte
	if len(f) >= 2 {
		ui, _ := strconv.ParseUint(f[1], 10, 32)
		keyID = uint32(ui)
	}
	if len(f) >= 3 && f[2] != "-" {
		b, err := base64.RawStdEncoding.DecodeString(f[2])
		if err == nil {
			curSalt = b
		}
	}
	if len(f) >= 4 {
		ui, _ := strconv.ParseUint(f[3], 10, 32)
		prevID = uint32(ui)
	}
	if len(f) >= 5 && f[4] != "-" {
		b, err := base64.RawStdEncoding.DecodeString(f[4])
		if err == nil {
			prevSalt = b
		}
	}
	ks, err := udpproto.NewKeySet(mode, token, keyID, curSalt, prevID, prevSalt)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.ks = ks
	s.mu.Unlock()
}
