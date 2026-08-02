package agent

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"hostit/shared/apitypes"
)

func TestRouteRequestDoesNotUsePendingControlHandshake(t *testing.T) {
	agentConn, peerConn := net.Pipe()
	defer agentConn.Close()
	defer peerConn.Close()

	a := NewAgent(Config{})
	a.mu.Lock()
	a.pendingControlConn = agentConn
	a.mu.Unlock()

	_, err := a.SendRouteRequest(context.Background(), apitypes.RouteRequest{RequestID: "pending-handshake"})
	if err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("route request error = %v, want not connected", err)
	}

	if err := peerConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if n, err := peerConn.Read(one[:]); err == nil || n != 0 {
		t.Fatalf("pending handshake received route-frame bytes: n=%d err=%v", n, err)
	}
}

func TestStopClosesPendingAndReadyControlConnections(t *testing.T) {
	ready, readyPeer := net.Pipe()
	pending, pendingPeer := net.Pipe()
	defer readyPeer.Close()
	defer pendingPeer.Close()

	a := NewAgent(Config{})
	a.mu.Lock()
	a.controlConn = ready
	a.pendingControlConn = pending
	a.mu.Unlock()
	a.Stop()

	for name, peer := range map[string]net.Conn{"ready": readyPeer, "pending": pendingPeer} {
		var one [1]byte
		if n, err := peer.Read(one[:]); err == nil || n != 0 {
			t.Fatalf("%s control connection remained open: n=%d err=%v", name, n, err)
		}
	}
}
