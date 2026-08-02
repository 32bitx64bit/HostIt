package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"hostit/shared/crypto"
)

func testUDPControlNonce(seed byte) crypto.UDPControlNonce {
	var nonce crypto.UDPControlNonce
	for i := range nonce {
		nonce[i] = seed + byte(i)
	}
	return nonce
}

func testUDPSessionID(seed byte) crypto.UDPSessionID {
	var sessionID crypto.UDPSessionID
	for i := range sessionID {
		sessionID[i] = seed + byte(i)
	}
	return sessionID
}

func testUDPAddr(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

func TestUDPRegisterReplayCacheIsBoundedPerAgent(t *testing.T) {
	cache := newUDPRegisterReplayCache()
	now := time.Now().UnixNano()
	expires := now + int64(udpRegisterAuthWindow)
	gen1 := testUDPControlNonce(10)
	gen2 := testUDPControlNonce(20)

	for i := 0; i < maxSeenUDPRegistersPerAgent; i++ {
		var key crypto.UDPRegisterKey
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		if !cache.record("agent-a", gen1, key, expires, now) {
			t.Fatalf("record %d rejected before per-agent bound", i)
		}
		if seen, full := cache.status("agent-a", gen1, key, now); !seen || full {
			t.Fatalf("record %d was not recognized as a replay", i)
		}
	}

	var overflow crypto.UDPRegisterKey
	overflow[0] = 0xff
	overflow[1] = 0xff
	if seen, full := cache.status("agent-a", gen1, overflow, now); seen || !full {
		t.Fatalf("full generation status = seen %t full %t, want false/true", seen, full)
	}
	if cache.record("agent-a", gen1, overflow, expires, now) {
		t.Fatal("per-agent replay cache admitted an entry above its hard bound")
	}
	if !cache.record("agent-b", gen1, overflow, expires, now) {
		t.Fatal("one agent's replay flood blocked another agent")
	}
	if !cache.record("agent-a", gen2, overflow, expires, now) {
		t.Fatal("new control generation did not receive a fresh replay bucket")
	}
	if seen, full := cache.status("agent-a", gen2, overflow, now); !seen || full {
		t.Fatalf("replacement generation status = seen %t full %t, want true/false", seen, full)
	}
	var oldKey crypto.UDPRegisterKey
	if seen, _ := cache.status("agent-a", gen1, oldKey, now); seen {
		t.Fatal("old control generation remained cached after replacement")
	}

	cache.prune(expires + 1)
	if len(cache.entries) != 0 {
		t.Fatalf("expired replay buckets retained: %d", len(cache.entries))
	}
	if !cache.record("agent-a", gen2, overflow, expires+1+int64(udpRegisterAuthWindow), expires+1) {
		t.Fatal("expired entries did not release per-agent capacity")
	}
}

func TestUDPRegisterReplayCacheRetainsFutureSkewedProof(t *testing.T) {
	cache := newUDPRegisterReplayCache()
	now := time.Now()
	created := now.Add(29 * time.Second)
	expires := created.Add(udpRegisterAuthWindow)
	key := crypto.UDPRegisterKey{1}
	nonce := testUDPControlNonce(1)

	if !cache.record("agent-a", nonce, key, expires.UnixNano(), now.UnixNano()) {
		t.Fatal("future-skewed proof was not recorded")
	}
	// This is after the old now+window retention would have expired, but the
	// signed proof remains fresh until created+window.
	if seen, _ := cache.status("agent-a", nonce, key, now.Add(31*time.Second).UnixNano()); !seen {
		t.Fatal("future-skewed proof was forgotten while it remained valid")
	}
	if seen, _ := cache.status("agent-a", nonce, key, expires.UnixNano()); !seen {
		t.Fatal("proof was forgotten at its inclusive freshness boundary")
	}
	if seen, _ := cache.status("agent-a", nonce, key, expires.Add(time.Nanosecond).UnixNano()); seen {
		t.Fatal("proof remained cached after its complete freshness window")
	}
}

func TestUDPAgentCOWMutationsPreserveConcurrentEntries(t *testing.T) {
	const (
		rounds     = 20
		agentCount = 48
	)

	for round := 0; round < rounds; round++ {
		srv := NewServer(ServerConfig{}, nil)
		staleAt := time.Now().Add(-2 * udpRegisterTimeout).UnixNano()
		for i := 0; i < agentCount; i++ {
			id := fmt.Sprintf("stale-%d", i)
			srv.updateUDPAgentAddr(id, testUDPAddr(uint16(10000+i)), testUDPSessionID(byte(i)), testUDPControlNonce(byte(i)), staleAt)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(agentCount + 1)
		go func() {
			defer wg.Done()
			<-start
			srv.pruneUDPAgents(time.Now().UnixNano())
		}()
		for i := 0; i < agentCount; i++ {
			i := i
			go func() {
				defer wg.Done()
				<-start
				id := fmt.Sprintf("fresh-%d", i)
				srv.updateUDPAgentAddr(id, testUDPAddr(uint16(20000+i)), testUDPSessionID(byte(i+64)), testUDPControlNonce(byte(i+64)), time.Now().UnixNano())
			}()
		}
		close(start)
		wg.Wait()

		snapshot := srv.loadUDPAgents()
		if len(snapshot) != agentCount {
			t.Fatalf("round %d: snapshot has %d entries, want %d", round, len(snapshot), agentCount)
		}
		for i := 0; i < agentCount; i++ {
			if snapshot[fmt.Sprintf("fresh-%d", i)] == nil {
				t.Fatalf("round %d: concurrent prune lost fresh-%d", round, i)
			}
			if snapshot[fmt.Sprintf("stale-%d", i)] != nil {
				t.Fatalf("round %d: stale-%d survived prune", round, i)
			}
		}

		start = make(chan struct{})
		wg = sync.WaitGroup{}
		wg.Add(agentCount)
		for i := 0; i < agentCount; i++ {
			i := i
			go func() {
				defer wg.Done()
				<-start
				id := fmt.Sprintf("fresh-%d", i)
				if i%2 == 0 {
					srv.clearUDPAgent(id)
					return
				}
				srv.updateUDPAgentAddr(id, testUDPAddr(uint16(30000+i)), testUDPSessionID(byte(i+96)), testUDPControlNonce(byte(i+96)), time.Now().UnixNano())
			}()
		}
		close(start)
		wg.Wait()

		snapshot = srv.loadUDPAgents()
		if len(snapshot) != agentCount/2 {
			t.Fatalf("round %d: post-clear snapshot has %d entries, want %d", round, len(snapshot), agentCount/2)
		}
		for i := 0; i < agentCount; i++ {
			st := snapshot[fmt.Sprintf("fresh-%d", i)]
			if i%2 == 0 && st != nil {
				t.Fatalf("round %d: cleared fresh-%d survived", round, i)
			}
			if i%2 == 1 && (st == nil || st.addr.Port() != uint16(30000+i)) {
				t.Fatalf("round %d: concurrent clear lost or reverted fresh-%d", round, i)
			}
		}
	}
}

func TestStaleUDPGraceExpiryPreservesReplacementGeneration(t *testing.T) {
	srv := NewServer(ServerConfig{}, nil)
	const agentID = "agent-a"
	addr := testUDPAddr(40000)
	sessionID := testUDPSessionID(1)
	gen1 := testUDPControlNonce(1)
	gen2 := testUDPControlNonce(2)

	srv.updateUDPAgentAddr(agentID, addr, sessionID, gen1, time.Now().UnixNano())
	st1 := srv.loadUDPAgents()[agentID]
	if st1 == nil || st1.controlNonce != gen1 {
		t.Fatal("first control generation was not installed")
	}

	stale := &udpGraceTimer{controlNonce: gen1, timer: time.NewTimer(time.Hour)}
	defer stale.timer.Stop()
	srv.udpAgentsMu.Lock()
	srv.udpGraceTimers[agentID] = stale
	srv.udpAgentsMu.Unlock()

	// The real agent keeps the same UDP socket and UDP session ID through a TCP
	// reconnect. Control generation must therefore participate in replacement.
	srv.updateUDPAgentAddr(agentID, addr, sessionID, gen2, time.Now().UnixNano())
	st2 := srv.loadUDPAgents()[agentID]
	if st2 == nil || st2.controlNonce != gen2 {
		t.Fatal("replacement control generation was not installed")
	}
	if st2 == st1 {
		t.Fatal("same addr/session fast path ignored the replacement control generation")
	}

	// Model an already-running stale callback that still owns its timer slot.
	// The state-generation check must preserve the replacement even then.
	srv.udpAgentsMu.Lock()
	srv.udpGraceTimers[agentID] = stale
	srv.udpAgentsMu.Unlock()
	srv.expireUDPAgent(agentID, stale)
	if st := srv.loadUDPAgents()[agentID]; st == nil || st.controlNonce != gen2 {
		t.Fatal("stale generation-1 grace callback cleared generation 2")
	}

	current := &udpGraceTimer{controlNonce: gen2, timer: time.NewTimer(time.Hour)}
	defer current.timer.Stop()
	srv.udpAgentsMu.Lock()
	srv.udpGraceTimers[agentID] = current
	srv.udpAgentsMu.Unlock()
	srv.expireUDPAgent(agentID, current)
	if srv.loadUDPAgents()[agentID] != nil {
		t.Fatal("current generation grace callback did not clear its own state")
	}
}

func TestServerStopDrainsGraceScheduledByDisconnect(t *testing.T) {
	srv := NewServer(ServerConfig{}, nil)
	srv.ctx, srv.cancel = context.WithCancel(context.Background())
	srv.updateUDPAgentAddr("agent-a", testUDPAddr(41000), testUDPSessionID(3), testUDPControlNonce(3), time.Now().UnixNano())

	// Model the control goroutine's deferred disconnect cleanup: it cannot run
	// until Stop cancels the server, which is after Stop's initial timer drain.
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		<-srv.ctx.Done()
		srv.sessionsMu.Lock()
		srv.scheduleUDPAgentClearLocked("agent-a")
		srv.sessionsMu.Unlock()
	}()

	srv.Stop()
	srv.udpAgentsMu.Lock()
	defer srv.udpAgentsMu.Unlock()
	if len(srv.udpGraceTimers) != 0 {
		t.Fatalf("Stop returned with %d UDP grace timers", len(srv.udpGraceTimers))
	}
}

func TestServerStopClosesActiveControlSession(t *testing.T) {
	srv := NewServer(ServerConfig{}, nil)
	srv.ctx, srv.cancel = context.WithCancel(context.Background())
	serverConn, peerConn := net.Pipe()
	defer peerConn.Close()
	sessionCtx, sessionCancel := context.WithCancel(srv.ctx)
	srv.sessions["agent-a"] = &agentSession{
		conn:    serverConn,
		cancel:  sessionCancel,
		agentID: "agent-a",
	}

	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		var one [1]byte
		_, _ = serverConn.Read(one[:])
		<-sessionCtx.Done()
	}()

	done := make(chan struct{})
	go func() {
		srv.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop waited for the control read deadline instead of closing the session")
	}
	if len(srv.sessions) != 0 {
		t.Fatalf("Stop retained %d control sessions", len(srv.sessions))
	}
}
