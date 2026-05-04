package agent

import (
	"strings"
	"testing"
)

func TestRemoteRouteEffectiveLocalAddr(t *testing.T) {
	t.Run("uses explicit local addr", func(t *testing.T) {
		rt := RemoteRoute{PublicAddr: ":80", LocalAddr: "127.0.0.1:3000"}
		if got := rt.EffectiveLocalAddr(); got != "127.0.0.1:3000" {
			t.Fatalf("EffectiveLocalAddr() = %q, want %q", got, "127.0.0.1:3000")
		}
	})

	t.Run("falls back to public port", func(t *testing.T) {
		rt := RemoteRoute{PublicAddr: ":8080"}
		if got := rt.EffectiveLocalAddr(); got != "127.0.0.1:8080" {
			t.Fatalf("EffectiveLocalAddr() = %q, want %q", got, "127.0.0.1:8080")
		}
	})

	t.Run("falls back from host public addr", func(t *testing.T) {
		rt := RemoteRoute{PublicAddr: "0.0.0.0:25565"}
		if got := rt.EffectiveLocalAddr(); got != "127.0.0.1:25565" {
			t.Fatalf("EffectiveLocalAddr() = %q, want %q", got, "127.0.0.1:25565")
		}
	})

	t.Run("empty public addr uses loopback host", func(t *testing.T) {
		rt := RemoteRoute{}
		if got := rt.EffectiveLocalAddr(); got != "127.0.0.1" {
			t.Fatalf("EffectiveLocalAddr() = %q, want %q", got, "127.0.0.1")
		}
	})
}

func TestConfigControlAndDataAddr(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		controlAddr string
		dataAddr    string
	}{
		{name: "host only", server: "example.com", controlAddr: "example.com:7000", dataAddr: "example.com:7001"},
		{name: "explicit port", server: "example.com:9000", controlAddr: "example.com:9000", dataAddr: "example.com:9001"},
		{name: "empty host", server: ":8000", controlAddr: "127.0.0.1:8000", dataAddr: "127.0.0.1:8001"},
		{name: "ipv6", server: "[::1]:7000", controlAddr: "[::1]:7000", dataAddr: "[::1]:7001"},
		{name: "data port overflow", server: "127.0.0.1:65535", controlAddr: "127.0.0.1:65535", dataAddr: "127.0.0.1:7001"},
		{name: "non numeric port", server: "example.com:not-a-port", controlAddr: "example.com:not-a-port", dataAddr: "example.com:7001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Server: tt.server}
			if got := cfg.ControlAddr(); got != tt.controlAddr {
				t.Fatalf("ControlAddr() = %q, want %q", got, tt.controlAddr)
			}
			if got := cfg.DataAddr(); got != tt.dataAddr {
				t.Fatalf("DataAddr() = %q, want %q", got, tt.dataAddr)
			}
		})
	}
}

func TestConfigValidateTLSPin(t *testing.T) {
	valid := Config{Server: "127.0.0.1:7000", Token: "token", TLSPinSHA256: strings.Repeat("A", 64)}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() with uppercase hex pin: %v", err)
	}

	shortPin := Config{Server: "127.0.0.1:7000", Token: "token", TLSPinSHA256: "abc"}
	if err := shortPin.Validate(); err == nil {
		t.Fatal("Validate() short TLS pin error = nil")
	}

	badHex := Config{Server: "127.0.0.1:7000", Token: "token", TLSPinSHA256: strings.Repeat("g", 64)}
	if err := badHex.Validate(); err == nil {
		t.Fatal("Validate() non-hex TLS pin error = nil")
	}

	missingBasics := Config{TLSPinSHA256: strings.Repeat("a", 64)}
	if err := missingBasics.Validate(); err == nil {
		t.Fatal("Validate() missing server/token error = nil")
	}
}
