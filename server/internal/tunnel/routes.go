package tunnel

import (
	"fmt"
	"strings"
)

func normalizeRoutes(cfg *ServerConfig) {
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
		cfg.Routes[i].LocalAddr = strings.TrimSpace(cfg.Routes[i].LocalAddr)
	}
}
