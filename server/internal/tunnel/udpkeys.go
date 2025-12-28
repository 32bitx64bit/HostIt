package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"
)

const udpKeyRotateAfter = 60 * 24 * time.Hour

func normalizeUDPEncryptionMode(cfg *ServerConfig) string {
	m := strings.ToLower(strings.TrimSpace(cfg.UDPEncryptionMode))
	switch m {
	case "none", "aes128", "aes256":
		return m
	case "":
		if cfg.DisableUDPEncryption {
			return "none"
		}
		return "aes256"
	default:
		// Unknown -> safest default.
		return "aes256"
	}
}

func ensureUDPSaltB64(s string) (string, bool) {
	if strings.TrimSpace(s) != "" {
		// Validate decode; if it fails, regenerate.
		if _, err := base64.RawStdEncoding.DecodeString(s); err == nil {
			return s, false
		}
	}
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawStdEncoding.EncodeToString(b[:]), true
}

// EnsureUDPKeys normalizes UDP encryption mode and makes sure key material exists.
// If keys are missing/invalid, it generates them. If the key is older than 60 days,
// it rotates it.
//
// Returns true if cfg was modified.
func EnsureUDPKeys(cfg *ServerConfig, now time.Time) (changed bool) {
	mode := normalizeUDPEncryptionMode(cfg)
	if cfg.UDPEncryptionMode != mode {
		cfg.UDPEncryptionMode = mode
		changed = true
	}

	// If encryption is off, we don't require keys.
	if mode == "none" {
		return changed
	}

	if cfg.UDPKeyID == 0 {
		cfg.UDPKeyID = 1
		changed = true
	}

	curSalt, regen := ensureUDPSaltB64(cfg.UDPKeySaltB64)
	if regen || cfg.UDPKeySaltB64 != curSalt {
		cfg.UDPKeySaltB64 = curSalt
		changed = true
	}

	if cfg.UDPKeyCreatedUnix == 0 {
		cfg.UDPKeyCreatedUnix = now.Unix()
		changed = true
	}

	// Rotate if expired.
	created := time.Unix(cfg.UDPKeyCreatedUnix, 0)
	if now.Sub(created) >= udpKeyRotateAfter {
		RotateUDPKeys(cfg, now)
		changed = true
	}

	return changed
}

// RotateUDPKeys generates a new current key and demotes the previous current key
// into the prev slot.
func RotateUDPKeys(cfg *ServerConfig, now time.Time) {
	cfg.UDPEncryptionMode = normalizeUDPEncryptionMode(cfg)
	if cfg.UDPEncryptionMode == "none" {
		return
	}

	// Demote current -> prev.
	if cfg.UDPKeyID != 0 && strings.TrimSpace(cfg.UDPKeySaltB64) != "" {
		cfg.UDPPrevKeyID = cfg.UDPKeyID
		cfg.UDPPrevKeySaltB64 = cfg.UDPKeySaltB64
	}

	if cfg.UDPKeyID == 0 {
		cfg.UDPKeyID = 1
	} else {
		cfg.UDPKeyID++
	}
	cfg.UDPKeySaltB64, _ = ensureUDPSaltB64("")
	cfg.UDPKeyCreatedUnix = now.Unix()
}
