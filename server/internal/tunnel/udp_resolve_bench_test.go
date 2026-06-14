package tunnel

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"hostit/shared/crypto"
)

// benchResolveServer builds a server with one UDP route owned by "agent-a",
// a registered UDP agent address, and a public UDP listener — the state the
// per-packet UDP forwarding path reads.
func benchResolveServer(b *testing.B) (*Server, func()) {
	b.Helper()
	srv := NewServer(ServerConfig{
		ControlAddr: "127.0.0.1:0",
		DataAddr:    "127.0.0.1:0",
		Token:       "x",
		DisableTLS:  true,
		Routes:      []RouteConfig{{Name: "rt", Proto: "udp", PublicAddr: ":0", Agent: "agent-a"}},
	}, nil)
	srv.updateRouteCache()
	srv.updateUDPAgentAddr("agent-a", netip.MustParseAddrPort("127.0.0.1:40000"), crypto.UDPSessionID{}, time.Now().UnixNano())
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		b.Fatal(err)
	}
	srv.mu.Lock()
	srv.publicUDP["rt"] = conn
	srv.mu.Unlock()
	return srv, func() { conn.Close() }
}

// BenchmarkUDPResolveDouble reflects the original agent->public resolution:
// routeOwner() plus a separate routeCache load hit the cache twice for the same
// route, and the client addr is parsed on every packet.
func BenchmarkUDPResolveDouble(b *testing.B) {
	srv, cleanup := benchResolveServer(b)
	defer cleanup()
	const clientID = "203.0.113.10:51820"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		owner := srv.routeOwner("rt")
		st := srv.loadUDPAgents()[owner]
		cache, _ := srv.routeCache.Load().(map[string]routeConfig)
		rc, rcOK := cache["rt"]
		ap, err := netip.ParseAddrPort(clientID)
		if st == nil || !rcOK || !rc.enabled || err != nil || !ap.IsValid() {
			b.Fatal("unexpected resolve failure")
		}
	}
}

// BenchmarkUDPResolveSingle reflects the optimized path: one route-cache load
// (owner+enabled together) and a cached client-addr parse.
func BenchmarkUDPResolveSingle(b *testing.B) {
	srv, cleanup := benchResolveServer(b)
	defer cleanup()
	const clientID = "203.0.113.10:51820"
	parseCache := map[string]netip.AddrPort{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc, rcOK := srv.getRouteConfig("rt")
		owner := rc.owner
		st := srv.loadUDPAgents()[owner]
		ap, ok := parseCache[clientID]
		if !ok {
			ap, _ = netip.ParseAddrPort(clientID)
			parseCache[clientID] = ap
		}
		if st == nil || !rcOK || !rc.enabled || !ap.IsValid() {
			b.Fatal("unexpected resolve failure")
		}
	}
}

// BenchmarkParseAddrPort isolates the per-packet cost of parsing the inbound
// client address string, which the cached path avoids.
func BenchmarkParseAddrPort(b *testing.B) {
	const clientID = "203.0.113.10:51820"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ap, err := netip.ParseAddrPort(clientID)
		if err != nil || !ap.IsValid() {
			b.Fatal(err)
		}
	}
}

// BenchmarkPublicUDPRLock isolates the per-packet cost of reading the publicUDP
// map under s.mu, versus a lock-free read.
func BenchmarkPublicUDPRLock(b *testing.B) {
	srv, cleanup := benchResolveServer(b)
	defer cleanup()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		srv.mu.RLock()
		_, ok := srv.publicUDP["rt"]
		srv.mu.RUnlock()
		if !ok {
			b.Fatal("missing conn")
		}
	}
}
