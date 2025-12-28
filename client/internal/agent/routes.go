package agent

import "strings"

func normalizeRoutes(cfg *Config) {
	if len(cfg.Routes) == 0 && strings.TrimSpace(cfg.LocalAddr) != "" {
		cfg.Routes = []RouteConfig{{
			Name:         "default",
			Proto:        "tcp",
			LocalTCPAddr: cfg.LocalAddr,
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
		cfg.Routes[i].LocalTCPAddr = strings.TrimSpace(cfg.Routes[i].LocalTCPAddr)
		cfg.Routes[i].LocalUDPAddr = strings.TrimSpace(cfg.Routes[i].LocalUDPAddr)
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
