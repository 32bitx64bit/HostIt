package agent

import (
	"encoding/base64"
	"strconv"
	"strings"
	"sync"

	"hostit/shared/udputil"
)

type udpSecurityState struct {
	mu sync.RWMutex
	ks udputil.KeySet
}

func newUDPSecurityState() *udpSecurityState {
	return &udpSecurityState{ks: udputil.KeySet{Mode: udputil.ModeNone}}
}

func (s *udpSecurityState) ForceNone() {
	s.mu.Lock()
	s.ks = udputil.KeySet{Mode: udputil.ModeNone}
	s.mu.Unlock()
}

func (s *udpSecurityState) Get() udputil.KeySet {
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
	mode := udputil.NormalizeMode(f[0])
	if mode == udputil.ModeNone {
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
	ks, err := udputil.NewKeySet(mode, token, keyID, curSalt, prevID, prevSalt)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.ks = ks
	s.mu.Unlock()
}
