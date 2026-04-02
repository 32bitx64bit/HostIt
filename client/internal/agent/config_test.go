package agent

import "testing"

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
}
