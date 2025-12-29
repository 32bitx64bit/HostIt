package tunnel

import (
	"fmt"
	"strings"
)

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
				p := 4
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
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "tcp", "both":
		return true
	default:
		return false
	}
}

func routeHasUDP(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "udp", "both":
		return true
	default:
		return false
	}
}
