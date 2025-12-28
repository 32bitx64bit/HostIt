package tunnel

import "strings"

func normalizeRoutes(cfg *ServerConfig) {
	if len(cfg.Routes) == 0 && strings.TrimSpace(cfg.PublicAddr) != "" {
		cfg.Routes = []RouteConfig{{
			Name:       "default",
			Proto:      "tcp",
			PublicAddr: cfg.PublicAddr,
		}}
	}
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
