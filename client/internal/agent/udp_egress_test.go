package agent

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

type blockingAgentUDPWriter struct {
	firstOnce sync.Once
	started   chan struct{}
	release   chan struct{}
	writes    chan []byte

	mu        sync.Mutex
	active    int
	maxActive int
}

func newBlockingAgentUDPWriter() *blockingAgentUDPWriter {
	return &blockingAgentUDPWriter{
		started: make(chan struct{}),
		release: make(chan struct{}),
		writes:  make(chan []byte, 32),
	}
}

func (w *blockingAgentUDPWriter) SetWriteDeadline(time.Time) error { return nil }

func (w *blockingAgentUDPWriter) WriteToUDP(payload []byte, _ *net.UDPAddr) (int, error) {
	w.mu.Lock()
	w.active++
	if w.active > w.maxActive {
		w.maxActive = w.active
	}
	w.mu.Unlock()

	w.firstOnce.Do(func() {
		close(w.started)
		<-w.release
	})
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
			t.Fatalf("unmarshal egress packet: %v", err)
		}
		return *pkt
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP egress write")
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

func TestAgentUDPEgressFairlySchedulesRoutesWithOneWriter(t *testing.T) {
	a := NewAgent(Config{Routes: map[string]RemoteRoute{
		"video":   {Name: "video"},
		"control": {Name: "control"},
	}})
	videoEpoch := agentRouteEpoch(t, a, "video")
	controlEpoch := agentRouteEpoch(t, a, "control")

	writer := newBlockingAgentUDPWriter()
	egress, err := newAgentUDPEgress(a, writer, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7001})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go egress.run(ctx)

	if err := egress.enqueueData("video", "client", videoEpoch, []byte("video-0")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first video write did not enter sink")
	}
	if err := egress.enqueueData("video", "client", videoEpoch, []byte("video-1")); err != nil {
		t.Fatal(err)
	}
	if err := egress.enqueueData("video", "client", videoEpoch, []byte("video-2")); err != nil {
		t.Fatal(err)
	}
	if err := egress.enqueueData("control", "client", controlEpoch, []byte("input")); err != nil {
		t.Fatal(err)
	}
	close(writer.release)

	first := nextAgentUDPPacket(t, writer.writes)
	second := nextAgentUDPPacket(t, writer.writes)
	third := nextAgentUDPPacket(t, writer.writes)
	fourth := nextAgentUDPPacket(t, writer.writes)
	if first.Route != "video" || string(first.Payload) != "video-0" {
		t.Fatalf("first packet = route %q payload %q, want in-flight video", first.Route, first.Payload)
	}
	if second.Route != "video" || string(second.Payload) != "video-1" {
		t.Fatalf("second packet = route %q payload %q, want at most one queued video before control", second.Route, second.Payload)
	}
	if third.Route != "control" || string(third.Payload) != "input" {
		t.Fatalf("third packet = route %q payload %q, want newly active control", third.Route, third.Payload)
	}
	if fourth.Route != "video" || string(fourth.Payload) != "video-2" {
		t.Fatalf("fourth packet = route %q payload %q, want remaining video", fourth.Route, fourth.Payload)
	}
	writer.mu.Lock()
	maxActive := writer.maxActive
	writer.mu.Unlock()
	if maxActive != 1 {
		t.Fatalf("concurrent socket writers = %d, want exactly one", maxActive)
	}
}

func TestAgentUDPEgressRegistrationUsesSystemPriority(t *testing.T) {
	a := NewAgent(Config{Routes: map[string]RemoteRoute{"video": {Name: "video"}}})
	videoEpoch := agentRouteEpoch(t, a, "video")
	writer := newBlockingAgentUDPWriter()
	egress, err := newAgentUDPEgress(a, writer, &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go egress.run(ctx)

	_ = egress.enqueueData("video", "client", videoEpoch, []byte("video-0"))
	<-writer.started
	_ = egress.enqueueData("video", "client", videoEpoch, []byte("video-1"))
	a.mu.Lock()
	a.udpRegisterReady = true
	a.mu.Unlock()
	if err := egress.enqueueRegister(crypto.UDPControlNonce{}, []byte("proof")); err != nil {
		t.Fatal(err)
	}
	close(writer.release)
	_ = nextAgentUDPPacket(t, writer.writes)
	if pkt := nextAgentUDPPacket(t, writer.writes); pkt.Type != protocol.TypeRegister || string(pkt.Payload) != "proof" {
		t.Fatalf("second packet = type %d payload %q, want system registration", pkt.Type, pkt.Payload)
	}
}

func TestAgentUDPEgressDropsQueuedStaleControlGeneration(t *testing.T) {
	a := NewAgent(Config{Routes: map[string]RemoteRoute{"video": {Name: "video"}}})
	videoEpoch := agentRouteEpoch(t, a, "video")
	oldNonce := crypto.UDPControlNonce{1}
	newNonce := crypto.UDPControlNonce{2}
	a.mu.Lock()
	a.udpControlNonce = oldNonce
	a.udpRegisterReady = true
	a.mu.Unlock()

	writer := newBlockingAgentUDPWriter()
	egress, err := newAgentUDPEgress(a, writer, &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go egress.run(ctx)

	if err := egress.enqueueData("video", "client", videoEpoch, []byte("in-flight")); err != nil {
		t.Fatal(err)
	}
	<-writer.started
	if err := egress.enqueueRegister(oldNonce, []byte("stale-proof")); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.udpControlNonce = newNonce
	a.mu.Unlock()
	if err := egress.enqueueRegister(newNonce, []byte("current-proof")); err != nil {
		t.Fatal(err)
	}
	close(writer.release)

	if pkt := nextAgentUDPPacket(t, writer.writes); pkt.Type != protocol.TypeData {
		t.Fatalf("first packet type = %d, want in-flight data", pkt.Type)
	}
	if pkt := nextAgentUDPPacket(t, writer.writes); pkt.Type != protocol.TypeRegister || string(pkt.Payload) != "current-proof" {
		t.Fatalf("packet after stale proof = type %d payload %q, want current proof", pkt.Type, pkt.Payload)
	}
}

func TestAgentUDPEgressDropsQueuedStaleRouteEpoch(t *testing.T) {
	initialRoute := RemoteRoute{Name: "video", LocalAddr: "127.0.0.1:5000"}
	a := NewAgent(Config{Routes: map[string]RemoteRoute{"video": initialRoute}})
	oldEpoch := agentRouteEpoch(t, a, "video")

	writer := newBlockingAgentUDPWriter()
	egress, err := newAgentUDPEgress(a, writer, &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go egress.run(ctx)

	if err := egress.enqueueData("video", "client", oldEpoch, []byte("in-flight")); err != nil {
		t.Fatal(err)
	}
	<-writer.started
	if err := egress.enqueueData("video", "client", oldEpoch, []byte("stale")); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.replaceRoutesLocked(map[string]RemoteRoute{
		"video": {Name: "video", LocalAddr: "127.0.0.1:5001"},
	})
	newEpoch := a.routeEpochs["video"]
	a.mu.Unlock()
	if newEpoch == 0 || newEpoch == oldEpoch {
		t.Fatalf("route epoch did not advance: old=%d new=%d", oldEpoch, newEpoch)
	}
	if err := egress.enqueueData("video", "client", newEpoch, []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	close(writer.release)

	if pkt := nextAgentUDPPacket(t, writer.writes); string(pkt.Payload) != "in-flight" {
		t.Fatalf("first payload = %q, want in-flight", pkt.Payload)
	}
	if pkt := nextAgentUDPPacket(t, writer.writes); string(pkt.Payload) != "fresh" {
		t.Fatalf("packet after stale epoch = %q, want fresh", pkt.Payload)
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
	writer := newBlockingAgentUDPWriter()
	egress, err := newAgentUDPEgress(a, writer, &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go egress.run(ctx)

	_ = egress.enqueueData("video", "client", videoEpoch, []byte("video-0"))
	<-writer.started
	_ = egress.enqueueData("video", "client", videoEpoch, []byte("video-1"))
	_ = egress.enqueueData("video", "client", videoEpoch, []byte("video-2"))
	_ = egress.enqueueData("control", "client", controlEpoch, []byte("input"))
	close(writer.release)

	want := []string{"video-0", "video-1", "input", "video-2"}
	for i, wantPayload := range want {
		pkt := nextAgentUDPPacket(t, writer.writes)
		aad := crypto.AppendUDPDataAAD(nil, pkt.Route, pkt.Client)
		plaintext, err := peerCrypto.Dec.Open(nil, pkt.Payload, aad)
		if err != nil {
			t.Fatalf("wire packet %d failed ordered replay/decrypt check: %v", i, err)
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
	writer := newBlockingAgentUDPWriter()
	close(writer.release)
	egress, err := newAgentUDPEgress(a, writer, &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	a.udpEgress = egress
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go egress.run(ctx)

	a.sendUDPRegister()
	select {
	case data := <-writer.writes:
		t.Fatalf("register emitted before HELLO installed routes: %x", data)
	case <-time.After(20 * time.Millisecond):
	}

	// Model the atomic state transition performed after a valid initial HELLO.
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
