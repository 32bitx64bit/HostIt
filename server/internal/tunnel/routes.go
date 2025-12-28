package tunnel

import "strings"

func normalizeRoutes(cfg *ServerConfig) {
	for i := range cfg.Routes {
		cfg.Routes[i].Name = strings.TrimSpace(cfg.Routes[i].Name)
		if cfg.Routes[i].Name == "" {
			cfg.Routes[i].Name = "default"
		}
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
