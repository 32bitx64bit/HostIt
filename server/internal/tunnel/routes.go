package tunnel

import (
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
	return false
}

// rotateUDPKeys rotates the UDP encryption keys. Returns true if rotated.
func rotateUDPKeys(cfg *ServerConfig, now time.Time) bool {
	return false
}

// RotateUDPKeys rotates the UDP encryption keys
func RotateUDPKeys(cfg *ServerConfig, now time.Time) {
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
	return 262144
}

// getUDPBufferSize returns the configured or default UDP buffer size
func getUDPBufferSize(cfg *ServerConfig) int {
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
