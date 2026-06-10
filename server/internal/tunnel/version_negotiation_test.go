package tunnel

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

func negotiateAsAgent(t *testing.T, controlAddr, token, agentVersion string) (net.Conn, protocol.VersionPayload) {
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err = net.Dial("tcp", controlAddr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := crypto.AuthenticateClient(conn, token); err != nil {
		conn.Close()
		t.Fatalf("auth: %v", err)
	}
	verPayload, _ := json.Marshal(protocol.VersionPayload{Version: agentVersion})
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeVersionNegotiate, Payload: verPayload}); err != nil {
		conn.Close()
		t.Fatalf("write version: %v", err)
	}
	pkt, err := protocol.ReadPacket(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("read version reply: %v", err)
	}
	if pkt.Type != protocol.TypeVersionNegotiate {
		conn.Close()
		t.Fatalf("reply type = %d, want version negotiate", pkt.Type)
	}
	var vp protocol.VersionPayload
	if err := json.Unmarshal(pkt.Payload, &vp); err != nil {
		conn.Close()
		t.Fatalf("parse version reply: %v", err)
	}
	return conn, vp
}

// TestVersionMismatchRejectedWithReason: an authenticated peer with an
// incompatible major version must receive a structured rejection naming
// both versions, then a close — not a bare connection reset.
func TestVersionMismatchRejectedWithReason(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      []RouteConfig{{Name: "default", Proto: "tcp"}},
		Token:       "testtoken",
		PairTimeout: time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	conn, vp := negotiateAsAgent(t, controlAddr, "testtoken", "1.0.0")
	defer conn.Close()

	if vp.Error == "" {
		t.Fatal("server accepted an incompatible major version")
	}
	if !strings.Contains(vp.Error, "1.0.0") {
		t.Errorf("rejection reason %q does not name the agent version", vp.Error)
	}
	if vp.Version != protocol.ProtocolVersion {
		t.Errorf("rejection carries server version %q, want %q", vp.Version, protocol.ProtocolVersion)
	}
	// The server must close after rejecting.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := protocol.ReadPacket(conn); err == nil {
		t.Fatal("connection stayed open after version rejection")
	}
}

// TestSameMajorNewerMinorAccepted pins the fixed compatibility rule: a peer
// with the same major but different minor must be accepted in both
// directions (the old rule rejected any minor difference on one side).
func TestSameMajorNewerMinorAccepted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      []RouteConfig{{Name: "default", Proto: "tcp"}},
		Token:       "testtoken",
		PairTimeout: time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	for _, agentVer := range []string{
		protocol.ProtocolVersionParsed.String(),
		// Same major, newer minor and older patch permutations.
		"2.99.0",
		"2.0.99",
	} {
		conn, vp := negotiateAsAgent(t, controlAddr, "testtoken", agentVer)
		if vp.Error != "" {
			conn.Close()
			t.Fatalf("agent version %s rejected: %s", agentVer, vp.Error)
		}
		// HELLO must follow.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		pkt, err := protocol.ReadPacket(conn)
		if err != nil || pkt.Type != protocol.TypeHello {
			conn.Close()
			t.Fatalf("agent version %s: expected HELLO after negotiation, got type=%d err=%v", agentVer, pkt.Type, err)
		}
		conn.Close()
	}
}

// TestIncompatibleAgentDoesNotDisruptActiveAgent guards the negotiation
// reordering: a same-token peer with a wrong version (e.g. one un-updated
// machine in a reconnect loop) must not bump the epoch, abort pending
// pairs, displace the healthy agent, or leak a session entry.
func TestIncompatibleAgentDoesNotDisruptActiveAgent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, echoAddr := startEcho(t)
	defer echoLn.Close()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicLn, _ := net.Listen("tcp", "127.0.0.1:0")
	publicAddr := publicLn.Addr().String()
	publicLn.Close()

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      []RouteConfig{{Name: "default", Proto: "tcp", PublicAddr: publicAddr}},
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	go fakeAgent(ctx, controlAddr, dataAddr, echoAddr, "testtoken")
	waitEchoReady(t, publicAddr)

	srv.mu.RLock()
	epochBefore := srv.agentEpoch
	srv.mu.RUnlock()
	srv.sessionsMu.Lock()
	sessionsBefore := len(srv.sessions)
	srv.sessionsMu.Unlock()

	// Three rejected attempts, as a reconnect loop would produce.
	for i := 0; i < 3; i++ {
		conn, vp := negotiateAsAgent(t, controlAddr, "testtoken", "1.0.0")
		if vp.Error == "" {
			conn.Close()
			t.Fatal("incompatible agent was accepted")
		}
		conn.Close()
	}

	srv.mu.RLock()
	epochAfter := srv.agentEpoch
	agentStillSet := srv.agentTCP != nil
	srv.mu.RUnlock()
	if epochAfter != epochBefore {
		t.Errorf("agent epoch changed %d -> %d after rejected negotiations", epochBefore, epochAfter)
	}
	if !agentStillSet {
		t.Error("healthy agent was displaced by a rejected peer")
	}
	srv.sessionsMu.Lock()
	sessionsAfter := len(srv.sessions)
	srv.sessionsMu.Unlock()
	if sessionsAfter != sessionsBefore {
		t.Errorf("sessions leaked: %d -> %d", sessionsBefore, sessionsAfter)
	}

	// The healthy agent must still serve traffic.
	c, err := net.Dial("tcp", publicAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := []byte("still-alive\n")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(msg))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("tunnel broken after rejected negotiations: %v", err)
	}
	if string(reply) != string(msg) {
		t.Fatalf("echo mismatch: %q", reply)
	}
}
