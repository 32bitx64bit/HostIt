package agent

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateIdentityPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-identity.json")

	id, err := LoadOrCreateIdentity(path, "laptop-mc")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id.AgentID() != "laptop-mc" {
		t.Fatalf("agent id = %q, want laptop-mc", id.AgentID())
	}
	// The updater preserves this path across upgrades; it must be reported.
	if id.Path() != path {
		t.Fatalf("Path() = %q, want %q", id.Path(), path)
	}

	// Reload: same keypair and ID, and the config seed is ignored once persisted.
	again, err := LoadOrCreateIdentity(path, "something-different")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.AgentID() != "laptop-mc" {
		t.Fatalf("reloaded agent id = %q, want laptop-mc (persisted wins)", again.AgentID())
	}
	if !bytes.Equal(id.PublicKey(), again.PublicKey()) {
		t.Fatal("keypair changed across reload")
	}
}

func TestIdentitySetAndRegenerate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-identity.json")
	id, err := LoadOrCreateIdentity(path, "main-pc")
	if err != nil {
		t.Fatal(err)
	}

	if err := id.SetAgentID("main-pc-2"); err != nil {
		t.Fatal(err)
	}
	if reloaded, _ := LoadOrCreateIdentity(path, ""); reloaded.AgentID() != "main-pc-2" {
		t.Fatalf("SetAgentID not persisted, reloaded %q", reloaded.AgentID())
	}

	// Regeneration appends a suffix; doing it twice must not grow unbounded.
	first, err := id.RegenerateAgentID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "main-pc-2-") {
		t.Fatalf("regenerated id = %q, want main-pc-2-<hex>", first)
	}
	second, err := id.RegenerateAgentID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(second, "main-pc-2-") || strings.Count(second, "-") != strings.Count(first, "-") {
		t.Fatalf("second regen %q grew the id beyond first %q", second, first)
	}
	if second == first {
		t.Fatal("regeneration produced the same id twice")
	}
}
