package agent

import "testing"

func TestServerPublicAddrPrefersHelloValue(t *testing.T) {
	a := NewAgent(Config{Server: "10.0.0.1:7000", Token: "tok"})
	a.mu.Lock()
	a.serverPublicAddr = "203.0.113.10"
	a.mu.Unlock()

	if got := a.ServerPublicAddr(); got != "203.0.113.10" {
		t.Fatalf("ServerPublicAddr() = %q, want advertised address", got)
	}
}

func TestServerPublicAddrFallsBackToConfiguredServerHost(t *testing.T) {
	a := NewAgent(Config{Server: "tunnel.example.com:7000", Token: "tok"})
	if got := a.ServerPublicAddr(); got != "tunnel.example.com" {
		t.Fatalf("ServerPublicAddr() = %q, want configured host", got)
	}

	a = NewAgent(Config{Server: "198.51.100.20", Token: "tok"})
	if got := a.ServerPublicAddr(); got != "198.51.100.20" {
		t.Fatalf("ServerPublicAddr() = %q, want bare configured host", got)
	}
}
