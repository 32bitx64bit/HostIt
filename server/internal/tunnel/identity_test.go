package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"hostit/server/internal/appstore"
	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

func tempStore(t *testing.T) *appstore.Store {
	t.Helper()
	f, err := os.CreateTemp("", "tunnel-agents-*.db")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	t.Cleanup(func() { os.Remove(path) })
	st, err := appstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// controlNegotiate runs the control handshake with a fixed keypair and returns
// the server's version reply (AssignedAgentID / Conflict / Error).
func controlNegotiate(t *testing.T, controlAddr, token, agentID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, signWith ed25519.PrivateKey) protocol.VersionPayload {
	t.Helper()
	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", controlAddr)
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial control: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, serverNonce, err := crypto.AuthenticateClient(conn, token)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	sig := crypto.SignIdentityChallenge(signWith, serverNonce)
	payload, _ := json.Marshal(protocol.VersionPayload{
		Version: protocol.ProtocolVersion, AgentID: agentID, PublicKey: pub, IdentitySig: sig,
	})
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeVersionNegotiate, Payload: payload}); err != nil {
		t.Fatalf("write version: %v", err)
	}
	pkt, err := protocol.ReadPacket(conn)
	if err != nil {
		t.Fatalf("read version reply: %v", err)
	}
	var vp protocol.VersionPayload
	if err := json.Unmarshal(pkt.Payload, &vp); err != nil {
		t.Fatalf("parse version reply: %v", err)
	}
	return vp
}

func startIdentityServer(t *testing.T) (string, *Server) {
	t.Helper()
	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
	}, tempStore(t))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx) }()
	return controlAddr, srv
}

func TestAgentIdentityClaimReassumeConflict(t *testing.T) {
	controlAddr, _ := startIdentityServer(t)
	pubA, privA, _ := crypto.GenerateAgentIdentity()
	pubB, privB, _ := crypto.GenerateAgentIdentity()

	// Key A claims "laptop" (trust-on-first-use).
	vp := controlNegotiate(t, controlAddr, "testtoken", "laptop", pubA, privA, privA)
	if vp.Error != "" || vp.Conflict || vp.AssignedAgentID != "laptop" {
		t.Fatalf("claim reply = %+v", vp)
	}

	// Key A reconnecting re-assumes "laptop" even if it proposes another name.
	vp = controlNegotiate(t, controlAddr, "testtoken", "renamed-by-mistake", pubA, privA, privA)
	if vp.Conflict || vp.AssignedAgentID != "laptop" {
		t.Fatalf("re-assume reply = %+v", vp)
	}

	// Key B proposing the taken ID must be told to pick a new one.
	vp = controlNegotiate(t, controlAddr, "testtoken", "laptop", pubB, privB, privB)
	if !vp.Conflict {
		t.Fatalf("expected conflict for second key on same id, got %+v", vp)
	}
}

func TestAgentIdentityRejectsBadSignature(t *testing.T) {
	controlAddr, _ := startIdentityServer(t)
	pub, _, _ := crypto.GenerateAgentIdentity()
	_, wrongPriv, _ := crypto.GenerateAgentIdentity()

	// Sign with a key that doesn't match the advertised public key.
	vp := controlNegotiate(t, controlAddr, "testtoken", "laptop", pub, nil, wrongPriv)
	if vp.Error == "" {
		t.Fatalf("expected rejection for bad signature, got %+v", vp)
	}
}

func TestAgentIdentityOverrideIsAdopted(t *testing.T) {
	controlAddr, srv := startIdentityServer(t)
	pub, priv, _ := crypto.GenerateAgentIdentity()

	if vp := controlNegotiate(t, controlAddr, "testtoken", "laptop", pub, priv, priv); vp.AssignedAgentID != "laptop" {
		t.Fatalf("claim reply = %+v", vp)
	}
	if err := srv.OverrideAgentID(context.Background(), "laptop", "laptop-mc"); err != nil {
		t.Fatalf("override: %v", err)
	}
	// The same key, still proposing its old name, is told to adopt the new one.
	vp := controlNegotiate(t, controlAddr, "testtoken", "laptop", pub, priv, priv)
	if vp.Conflict || vp.AssignedAgentID != "laptop-mc" {
		t.Fatalf("post-override reply = %+v", vp)
	}
}
