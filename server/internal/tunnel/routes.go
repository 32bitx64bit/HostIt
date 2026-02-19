package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// EnsureUDPKeys generates UDP encryption keys if not already set.
// Returns true if keys were generated/updated, false otherwise.
func EnsureUDPKeys(cfg *ServerConfig, now time.Time) bool {
	if cfg == nil {
		return false
	}

	// If encryption is disabled, nothing to do
	if cfg.DisableUDPEncryption {
		return false
	}

	// If key ID is already set and not too old, nothing to do
	if cfg.UDPKeyID != 0 {
		// Check if key needs rotation (older than 60 days)
		if cfg.UDPKeyCreatedUnix > 0 {
			keyCreated := time.Unix(cfg.UDPKeyCreatedUnix, 0)
			if now.Sub(keyCreated) < 60*24*time.Hour {
				return false
			}
			// Key is old, rotate it
			return rotateUDPKeys(cfg, now)
		}
		return false
	}

	// Generate a new key ID based on timestamp
	cfg.UDPKeyID = uint32(now.Unix())
	cfg.UDPKeyCreatedUnix = now.Unix()

	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return false
	}
	cfg.UDPKeySaltB64 = base64.RawStdEncoding.EncodeToString(salt)

	return true
}

// rotateUDPKeys rotates the UDP encryption keys. Returns true if rotated.
func rotateUDPKeys(cfg *ServerConfig, now time.Time) bool {
	// Move current key to previous
	cfg.UDPPrevKeyID = cfg.UDPKeyID
	cfg.UDPPrevKeySaltB64 = cfg.UDPKeySaltB64

	// Generate new key
	cfg.UDPKeyID = uint32(now.Unix())
	cfg.UDPKeyCreatedUnix = now.Unix()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return false
	}
	cfg.UDPKeySaltB64 = base64.RawStdEncoding.EncodeToString(salt)
	return true
}

// RotateUDPKeys rotates the UDP encryption keys
func RotateUDPKeys(cfg *ServerConfig, now time.Time) {
	if cfg == nil || cfg.DisableUDPEncryption {
		return
	}

	// Move current key to previous
	cfg.UDPPrevKeyID = cfg.UDPKeyID
	cfg.UDPPrevKeySaltB64 = cfg.UDPKeySaltB64

	// Generate new key
	cfg.UDPKeyID = uint32(now.Unix())
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err == nil {
		cfg.UDPKeySaltB64 = base64.RawStdEncoding.EncodeToString(salt)
	}
}

// trySetUDPBuffers attempts to set the read and write buffer sizes for a UDP connection
func trySetUDPBuffers(conn *net.UDPConn, size int) (actualRead, actualWrite int) {
	if conn == nil {
		return 0, 0
	}

	_ = conn.SetReadBuffer(size)
	_ = conn.SetWriteBuffer(size)

	fd, err := conn.File()
	if err != nil {
		return 0, 0
	}
	defer fd.Close()

	fdInt := int(fd.Fd())
	actualRead, _ = unix.GetsockoptInt(fdInt, unix.SOL_SOCKET, unix.SO_RCVBUF)
	actualWrite, _ = unix.GetsockoptInt(fdInt, unix.SOL_SOCKET, unix.SO_SNDBUF)

	return actualRead / 2, actualWrite / 2
}

// getUDPWorkerCount returns the configured or default UDP worker count
func getUDPWorkerCount(cfg *ServerConfig) int {
	if cfg.UDPWorkerCount != nil && *cfg.UDPWorkerCount > 0 {
		return *cfg.UDPWorkerCount
	}
	workers := runtime.NumCPU() * 4
	if workers < 16 {
		workers = 16
	}
	if workers > 256 {
		workers = 256
	}
	return workers
}

// getUDPReaderCount returns the configured or default UDP reader count
func getUDPReaderCount(cfg *ServerConfig) int {
	if cfg.UDPReaderCount != nil && *cfg.UDPReaderCount > 0 {
		return *cfg.UDPReaderCount
	}
	readers := runtime.NumCPU()
	if readers < 4 {
		readers = 4
	}
	if readers > 32 {
		readers = 32
	}
	return readers
}

// getUDPQueueSize returns the configured or default UDP queue size
func getUDPQueueSize(cfg *ServerConfig) int {
	if cfg.UDPQueueSize != nil && *cfg.UDPQueueSize > 0 {
		return *cfg.UDPQueueSize
	}
	return 262144
}

// getUDPBufferSize returns the configured or default UDP buffer size
func getUDPBufferSize(cfg *ServerConfig) int {
	if cfg.UDPBufferSize != nil && *cfg.UDPBufferSize > 0 {
		return *cfg.UDPBufferSize
	}
	return 64 * 1024 * 1024
}

func normalizeRoutes(cfg *ServerConfig) {
	// Route names must be unique. The agent keys routes by name, and duplicate names
	// will cause one route to overwrite another (breaking multi-port forwarding).
	//
	// Additionally, when deduping we avoid generating a name that collides with any
	// explicitly configured name elsewhere in cfg.Routes (e.g. don't auto-generate
	// "app-2" if there is an actual "app-2" route).
	reserved := map[string]int{}
	for i := range cfg.Routes {
		name := strings.TrimSpace(cfg.Routes[i].Name)
		if name == "" {
			name = "default"
		}
		cfg.Routes[i].Name = name
		reserved[name]++
	}

	used := map[string]bool{}
	for i := range cfg.Routes {
		base := cfg.Routes[i].Name
		name := base
		if used[name] {
			n := 2
			for {
				cand := fmt.Sprintf("%s-%d", base, n)
				if !used[cand] && reserved[cand] == 0 {
					name = cand
					break
				}
				n++
			}
		}
		cfg.Routes[i].Name = name
		used[name] = true

		cfg.Routes[i].Proto = strings.ToLower(strings.TrimSpace(cfg.Routes[i].Proto))
		if cfg.Routes[i].Proto == "" {
			cfg.Routes[i].Proto = "tcp"
		}
		cfg.Routes[i].PublicAddr = strings.TrimSpace(cfg.Routes[i].PublicAddr)
		if cfg.Routes[i].TCPNoDelay == nil {
			b := true
			cfg.Routes[i].TCPNoDelay = &b
		}
		if cfg.Routes[i].TunnelTLS == nil {
			b := true
			cfg.Routes[i].TunnelTLS = &b
		}
		if cfg.Routes[i].Preconnect == nil {
			if routeHasTCP(cfg.Routes[i].Proto) {
				p := 4 // Increased from 2 for better high-throughput handling
				cfg.Routes[i].Preconnect = &p
			} else {
				p := 0
				cfg.Routes[i].Preconnect = &p
			}
		}
		if cfg.Routes[i].Preconnect != nil {
			p := *cfg.Routes[i].Preconnect
			if p < 0 {
				p = 0
			}
			if p > 64 {
				p = 64
			}
			*cfg.Routes[i].Preconnect = p
		}
	}
}

func routeHasTCP(proto string) bool {
	// proto is already normalized (lowercase, trimmed) by normalizeRoutes.
	switch proto {
	case "tcp", "both":
		return true
	default:
		return false
	}
}

func routeHasUDP(proto string) bool {
	// proto is already normalized (lowercase, trimmed) by normalizeRoutes.
	switch proto {
	case "udp", "both":
		return true
	default:
		return false
	}
}
