package tunnel

import (
	"sort"

	"hostit/shared/emailcfg"
)

type managedDomainEntry struct {
	Host               string
	HTTPSRouteName     string
	HTTPChallengeRoute string
}

type managedDomainSnapshot struct {
	entries    map[string]managedDomainEntry
	httpsHosts []string
}

type domainManager struct {
	server *Server
}

func newDomainManager(s *Server) *domainManager {
	return &domainManager{server: s}
}

func buildManagedDomainSnapshot(cfg ServerConfig) managedDomainSnapshot {
	entries := make(map[string]managedDomainEntry)
	for _, rt := range cfg.Routes {
		if !rt.IsEnabled() || !rt.IsDomainEnabled() {
			continue
		}
		host := normalizeHostname(rt.Domain)
		if host == "" {
			continue
		}
		entry := entries[host]
		entry.Host = host
		entry.HTTPSRouteName = rt.Name
		entries[host] = entry
	}

	email := emailcfg.Normalize(cfg.Email)
	if cfg.DomainManagerEnabled && email.Enabled && email.AutoTLS {
		host := normalizeHostname(email.EffectiveMailHost())
		if host != "" {
			entry := entries[host]
			entry.Host = host
			entry.HTTPChallengeRoute = internalEmailACMEHTTPRouteName
			entries[host] = entry
		}
	}

	httpsHosts := make([]string, 0, len(entries))
	for host, entry := range entries {
		if entry.HTTPSRouteName != "" {
			httpsHosts = append(httpsHosts, host)
		}
	}
	sort.Strings(httpsHosts)

	return managedDomainSnapshot{entries: entries, httpsHosts: httpsHosts}
}

func (m *domainManager) snapshot() managedDomainSnapshot {
	if m == nil || m.server == nil {
		return managedDomainSnapshot{entries: map[string]managedDomainEntry{}}
	}
	m.server.mu.RLock()
	cfg := m.server.cfg
	m.server.mu.RUnlock()
	return buildManagedDomainSnapshot(cfg)
}

func (m *domainManager) lookup(host string) (managedDomainEntry, bool) {
	host = normalizeHostname(host)
	if host == "" {
		return managedDomainEntry{}, false
	}
	entry, ok := m.snapshot().entries[host]
	return entry, ok
}

func (m *domainManager) lookupHTTPS(host string) (managedDomainEntry, bool) {
	entry, ok := m.lookup(host)
	if !ok || entry.HTTPSRouteName == "" {
		return managedDomainEntry{}, false
	}
	return entry, true
}

func (m *domainManager) httpsHosts() []string {
	snap := m.snapshot()
	out := make([]string, len(snap.httpsHosts))
	copy(out, snap.httpsHosts)
	return out
}

func (m *domainManager) defaultHTTPSHost() string {
	hosts := m.httpsHosts()
	if len(hosts) == 0 {
		return ""
	}
	return hosts[0] // hosts is already sorted; return the first one
}
