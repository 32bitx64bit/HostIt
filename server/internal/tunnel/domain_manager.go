package tunnel

import (
	"sort"
	"strings"
	"sync/atomic"

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

type domainRoutingSnapshot struct {
	managedDomainSnapshot
	routes         map[string]RouteConfig
	domainDisabled map[string]struct{}
}

type domainManager struct {
	server   *Server
	snapshot atomic.Value // stores *domainRoutingSnapshot
}

func newDomainManager(s *Server) *domainManager {
	m := &domainManager{server: s}
	m.snapshot.Store(&domainRoutingSnapshot{
		managedDomainSnapshot: managedDomainSnapshot{entries: map[string]managedDomainEntry{}},
		routes:                map[string]RouteConfig{},
		domainDisabled:        map[string]struct{}{},
	})
	return m
}

func buildManagedDomainSnapshot(cfg ServerConfig) managedDomainSnapshot {
	return buildManagedDomainSnapshotForRoutes(cfg, cfg.Routes)
}

func buildManagedDomainSnapshotForRoutes(cfg ServerConfig, routes []RouteConfig) managedDomainSnapshot {
	entries := make(map[string]managedDomainEntry)
	for _, rt := range routes {
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

// rebuildLocked publishes a complete immutable routing snapshot. Callers must
// hold server.mu while reading cfg and dynamicRoutes.
func (m *domainManager) rebuildLocked() {
	if m == nil || m.server == nil {
		return
	}
	cfg := m.server.cfg
	routes := effectiveRoutes(cfg, m.server.dynamicRoutes)
	managed := buildManagedDomainSnapshotForRoutes(cfg, routes)
	routeMap := make(map[string]RouteConfig, len(routes))
	for _, rt := range routes {
		routeMap[rt.Name] = rt
	}
	disabled := make(map[string]struct{}, len(cfg.DomainDisabledAgents))
	for _, id := range cfg.DomainDisabledAgents {
		if id = strings.TrimSpace(id); id != "" {
			disabled[id] = struct{}{}
		}
	}
	m.snapshot.Store(&domainRoutingSnapshot{
		managedDomainSnapshot: managed,
		routes:                routeMap,
		domainDisabled:        disabled,
	})
}

func (m *domainManager) load() *domainRoutingSnapshot {
	if m == nil {
		return nil
	}
	snap, _ := m.snapshot.Load().(*domainRoutingSnapshot)
	return snap
}

func (m *domainManager) lookup(host string) (managedDomainEntry, bool) {
	host = normalizeHostname(host)
	if host == "" {
		return managedDomainEntry{}, false
	}
	snap := m.load()
	if snap == nil {
		return managedDomainEntry{}, false
	}
	entry, ok := snap.entries[host]
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
	snap := m.load()
	if snap == nil {
		return nil
	}
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

func (m *domainManager) route(name string) (RouteConfig, bool) {
	snap := m.load()
	if snap == nil {
		return RouteConfig{}, false
	}
	rt, ok := snap.routes[name]
	return rt, ok
}

func (m *domainManager) domainEnabledForAgent(agentID string) bool {
	snap := m.load()
	if snap == nil {
		return true
	}
	_, disabled := snap.domainDisabled[agentID]
	return !disabled
}
