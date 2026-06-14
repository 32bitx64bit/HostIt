package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

// Identity is the agent's persistent Ed25519 keypair plus its current Agent ID.
// The keypair is generated once and never changes; the Agent ID is seeded from
// config on first run, then re-assumed across restarts (or replaced by a server
// override / conflict regeneration). The private key is the proof the server
// uses to know a reconnecting agent really is who it claims.
type Identity struct {
	path string // "" = ephemeral (not persisted)
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey

	mu      sync.Mutex
	agentID string
}

type identityFile struct {
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
	AgentID    string `json:"agent_id"`
}

// LoadOrCreateIdentity loads the keypair from path, generating and persisting a
// new one if absent or corrupt. initialAgentID seeds the Agent ID only on first
// creation; an existing file's Agent ID wins (the agent re-assumes it).
func LoadOrCreateIdentity(path, initialAgentID string) (*Identity, error) {
	initialAgentID = strings.TrimSpace(initialAgentID)
	if initialAgentID == "" {
		initialAgentID = protocol.DefaultAgentID
	}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var f identityFile
		if json.Unmarshal(data, &f) == nil &&
			len(f.PrivateKey) == ed25519.PrivateKeySize &&
			len(f.PublicKey) == ed25519.PublicKeySize {
			id := f.AgentID
			if strings.TrimSpace(id) == "" {
				id = initialAgentID
			}
			return &Identity{path: path, pub: f.PublicKey, priv: f.PrivateKey, agentID: id}, nil
		}
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("read identity %s: %w", path, err)
	}

	pub, priv, err := crypto.GenerateAgentIdentity()
	if err != nil {
		return nil, err
	}
	id := &Identity{path: path, pub: pub, priv: priv, agentID: initialAgentID}
	if err := id.persist(); err != nil {
		return nil, err
	}
	return id, nil
}

func newEphemeralIdentity(agentID string) (*Identity, error) {
	pub, priv, err := crypto.GenerateAgentIdentity()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(agentID) == "" {
		agentID = protocol.DefaultAgentID
	}
	return &Identity{pub: pub, priv: priv, agentID: agentID}, nil
}

func (id *Identity) Path() string      { return id.path }
func (id *Identity) PublicKey() []byte { return append([]byte(nil), id.pub...) }
func (id *Identity) Sign(challenge []byte) []byte {
	return crypto.SignIdentityChallenge(id.priv, challenge)
}

func (id *Identity) AgentID() string {
	id.mu.Lock()
	defer id.mu.Unlock()
	return id.agentID
}

// SetAgentID adopts a server-assigned ID and persists it.
func (id *Identity) SetAgentID(newID string) error {
	newID = strings.TrimSpace(newID)
	if newID == "" {
		return nil
	}
	id.mu.Lock()
	defer id.mu.Unlock()
	if id.agentID == newID {
		return nil
	}
	id.agentID = newID
	return id.persist()
}

// RegenerateAgentID picks a fresh ID after the server reports a conflict.
func (id *Identity) RegenerateAgentID() (string, error) {
	id.mu.Lock()
	defer id.mu.Unlock()
	base := id.agentID
	if i := strings.LastIndex(base, "-"); i > 0 && isHexSuffix(base[i+1:]) {
		base = base[:i]
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id.agentID = base + "-" + hex.EncodeToString(b[:])
	if err := id.persist(); err != nil {
		return "", err
	}
	return id.agentID, nil
}

// persist writes the identity atomically; the keypair never changes, so only
// callers that hold id.mu (or hold the only reference) may call it.
func (id *Identity) persist() error {
	if id.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(identityFile{PrivateKey: id.priv, PublicKey: id.pub, AgentID: id.agentID}, "", "  ")
	if err != nil {
		return err
	}
	tmp := id.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write identity %s: %w", id.path, err)
	}
	if err := os.Rename(tmp, id.path); err != nil {
		return fmt.Errorf("rename identity %s: %w", id.path, err)
	}
	return nil
}

func isHexSuffix(s string) bool {
	if len(s) != 8 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
