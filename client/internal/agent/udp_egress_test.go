package agent

import (
	"net"
	"sync"
	"testing"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

type recordingAgentUDPWriter struct {
	writes chan []byte

	mu        sync.Mutex
	active    int
	maxActive int
}

func newRecordingAgentUDPWriter() *recordingAgentUDPWriter {
	return &recordingAgentUDPWriter{writes: make(chan []byte, 32)}
}

func (w *recordingAgentUDPWriter) WriteToUDP(payload []byte, _ *net.UDPAddr) (int, error) {
	w.mu.Lock()
	w.active++
	if w.active > w.maxActive {
		w.maxActive = w.active
	}
	w.mu.Unlock()

	w.writes <- append([]byte(nil), payload...)

	w.mu.Lock()
	w.active--
	w.mu.Unlock()
	return len(payload), nil
}

func nextAgentUDPPacket(t *testing.T, writes <-chan []byte) protocol.Packet {
	t.Helper()
	select {
	case data := <-writes:
		pkt, err := protocol.UnmarshalUDP(data)
		if err != nil {
			t.Fatalf("unmarshal UDP packet: %v", err)
		}
		return *pkt
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP write")
		return protocol.Packet{}
	}
}

func agentRouteEpoch(t *testing.T, a *Agent, route string) uint64 {
	t.Helper()
	_, _, epoch, ok := a.currentUDPEgressRoute(route)
	if !ok || epoch == 0 {
		t.Fatalf("route %q has no active UDP egress epoch", route)
	}
	return epoch
}

func TestAgentUDPEgressSendsDataImmediately(t *testing.T) {
	a := NewAgent(Config{Routes: map[string]RemoteRoute{
		"control": {Name: "control"},
	}})
	epoch := agentRouteEpoch(t, a, "control")
	writer := newRecordingAgentUDPWriter()
	egress := newAgentUDPEgress(a, writer, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7001})

	egress.sendData("control", "client", epoch, []byte("input"))
	pkt := nextAgentUDPPacket(t, writer.writes)
	if pkt.Route != "control" || string(pkt.Payload) != "input" {
		t.Fatalf("packet = route %q payload %q, want control/input", pkt.Route, pkt.Payload)
	}
}

func TestAgentUDPEgressDropsStaleRouteEpoch(t *testing.T) {
	a := NewAgent(Config{Routes: map[string]RemoteRoute{
		"video": {Name: "video", LocalAddr: "127.0.0.1:5000"},
	}})
	oldEpoch := agentRouteEpoch(t, a, "video")
	writer := newRecordingAgentUDPWriter()
	egress := newAgentUDPEgress(a, writer, &net.UDPAddr{})

	a.mu.Lock()
	a.replaceRoutesLocked(map[string]RemoteRoute{
		"video": {Name: "video", LocalAddr: "127.0.0.1:5001"},
	})
	newEpoch := a.routeEpochs["video"]
	a.mu.Unlock()
	if newEpoch == 0 || newEpoch == oldEpoch {
		t.Fatalf("route epoch did not advance: old=%d new=%d", oldEpoch, newEpoch)
	}

	egress.sendData("video", "client", oldEpoch, []byte("stale"))
	select {
	case <-writer.writes:
		t.Fatal("stale epoch was written")
	case <-time.After(20 * time.Millisecond):
	}

	egress.sendData("video", "client", newEpoch, []byte("fresh"))
	if pkt := nextAgentUDPPacket(t, writer.writes); string(pkt.Payload) != "fresh" {
		t.Fatalf("payload = %q, want fresh", pkt.Payload)
	}
}

func TestAgentUDPEgressDropsStaleControlGeneration(t *testing.T) {
	a := NewAgent(Config{Routes: map[string]RemoteRoute{"video": {Name: "video"}}})
	oldNonce := crypto.UDPControlNonce{1}
	newNonce := crypto.UDPControlNonce{2}
	a.mu.Lock()
	a.udpControlNonce = oldNonce
	a.udpRegisterReady = true
	a.mu.Unlock()

	writer := newRecordingAgentUDPWriter()
	egress := newAgentUDPEgress(a, writer, &net.UDPAddr{})

	a.mu.Lock()
	a.udpControlNonce = newNonce
	a.mu.Unlock()
	egress.sendRegister(oldNonce, []byte("stale-proof"))
	select {
	case <-writer.writes:
		t.Fatal("stale control generation was written")
	case <-time.After(20 * time.Millisecond):
	}

	egress.sendRegister(newNonce, []byte("current-proof"))
	pkt := nextAgentUDPPacket(t, writer.writes)
	if pkt.Type != protocol.TypeRegister || string(pkt.Payload) != "current-proof" {
		t.Fatalf("packet = type %d payload %q, want current proof", pkt.Type, pkt.Payload)
	}
}

func TestAgentUDPEgressEncryptionCountersFollowWireOrder(t *testing.T) {
	baseKey := make([]byte, 32)
	for i := range baseKey {
		baseKey[i] = byte(i + 1)
	}
	var sessionID crypto.UDPSessionID
	for i := range sessionID {
		sessionID[i] = byte(100 + i)
	}
	agentCrypto, err := crypto.NewUDPSessionCrypto(baseKey, sessionID[:], crypto.UDPDirClientToServer, crypto.UDPDirServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	peerCrypto, err := crypto.NewUDPSessionCrypto(baseKey, sessionID[:], crypto.UDPDirServerToClient, crypto.UDPDirClientToServer)
	if err != nil {
		t.Fatal(err)
	}

	a := NewAgent(Config{Routes: map[string]RemoteRoute{
		"video":   {Name: "video", Encrypted: true, Algorithm: "test"},
		"control": {Name: "control", Encrypted: true, Algorithm: "test"},
	}})
	a.udpCryptoByAlg = map[string]*crypto.UDPSessionCrypto{"test": agentCrypto}
	videoEpoch := agentRouteEpoch(t, a, "video")
	controlEpoch := agentRouteEpoch(t, a, "control")
	writer := newRecordingAgentUDPWriter()
	egress := newAgentUDPEgress(a, writer, &net.UDPAddr{})

	egress.sendData("video", "client", videoEpoch, []byte("video-0"))
	egress.sendData("video", "client", videoEpoch, []byte("video-1"))
	egress.sendData("control", "client", controlEpoch, []byte("input"))

	want := []string{"video-0", "video-1", "input"}
	for i, wantPayload := range want {
		pkt := nextAgentUDPPacket(t, writer.writes)
		aad := crypto.AppendUDPDataAAD(nil, pkt.Route, pkt.Client)
		plaintext, err := peerCrypto.Dec.Open(nil, pkt.Payload, aad)
		if err != nil {
			t.Fatalf("wire packet %d failed ordered decrypt: %v", i, err)
		}
		if string(plaintext) != wantPayload {
			t.Fatalf("wire packet %d plaintext = %q, want %q", i, plaintext, wantPayload)
		}
	}
}

func TestAgentSendUDPRegisterWaitsForHelloAndBindsControlGeneration(t *testing.T) {
	id, err := newEphemeralIdentity("agent-a")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := crypto.NewUDPSessionID()
	if err != nil {
		t.Fatal(err)
	}
	var controlNonce crypto.UDPControlNonce
	for i := range controlNonce {
		controlNonce[i] = byte(200 + i)
	}

	a := NewAgent(Config{Token: "test-token"})
	a.identity = id
	a.udpSessionID = sessionID
	a.udpControlNonce = controlNonce
	a.udpRegisterReady = false
	writer := newRecordingAgentUDPWriter()
	egress := newAgentUDPEgress(a, writer, &net.UDPAddr{})
	a.udpEgress = egress

	a.sendUDPRegister()
	select {
	case data := <-writer.writes:
		t.Fatalf("register emitted before HELLO installed routes: %x", data)
	case <-time.After(20 * time.Millisecond):
	}

	a.mu.Lock()
	a.replaceRoutesLocked(map[string]RemoteRoute{
		"control": {Name: "control", Proto: "udp", LocalAddr: "127.0.0.1:47999"},
	})
	a.routeCacheGen.Add(1)
	a.udpRegisterReady = true
	a.mu.Unlock()
	if _, _, _, ok := a.currentUDPEgressRoute("control"); !ok {
		t.Fatal("HELLO route was not installed before UDP registration became ready")
	}

	a.sendUDPRegister()
	pkt := nextAgentUDPPacket(t, writer.writes)
	if pkt.Type != protocol.TypeRegister {
		t.Fatalf("packet type = %d, want register", pkt.Type)
	}
	reg, ok := crypto.ParseBoundUDPRegister("test-token", pkt.Payload, time.Now(), time.Second)
	if !ok {
		t.Fatal("runtime emitted an invalid bound UDP register")
	}
	if reg.SessionID != sessionID || reg.ControlNonce != controlNonce || reg.AgentID != "agent-a" {
		t.Fatalf("bound register fields = session %x nonce %x agent %q", reg.SessionID, reg.ControlNonce, reg.AgentID)
	}
	if !reg.VerifyIdentity(id.PublicKey()) {
		t.Fatal("bound register did not verify against the active identity")
	}
}
