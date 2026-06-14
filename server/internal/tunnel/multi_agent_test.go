package tunnel

import (
	"context"
	"net"
	"testing"
	"time"
)

func multiAgentRoundTrip(addr, payload string, timeout time.Duration) (string, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte(payload)); err != nil {
		return "", err
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// waitRouteEcho retries until the route returns want, which also confirms readiness.
func waitRouteEcho(t *testing.T, addr, payload, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		got, err := multiAgentRoundTrip(addr, payload, 2*time.Second)
		if err == nil && got == want {
			return
		}
		last = got
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("route %s never echoed %q (last response %q)", addr, want, last)
}

// Two agents behind one loopback IP (the shared-public-IP case), each owning a route.
func TestMultiAgentTCPRoutingByOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoA, addrA := startPrefixedEcho(t, "A")
	defer echoA.Close()
	echoB, addrB := startPrefixedEcho(t, "B")
	defer echoB.Close()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicA := freeTCPAddr(t)
	publicB := freeTCPAddr(t)

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
		Routes: []RouteConfig{
			{Name: "route-a", Proto: "tcp", PublicAddr: publicA, Agent: "agent-a"},
			{Name: "route-b", Proto: "tcp", PublicAddr: publicB, Agent: "agent-b"},
		},
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	go fakeAgentRoutesAs(ctx, controlAddr, dataAddr, "agent-a", map[string]string{"route-a": addrA}, "testtoken")
	go fakeAgentRoutesAs(ctx, controlAddr, dataAddr, "agent-b", map[string]string{"route-b": addrB}, "testtoken")

	waitRouteEcho(t, publicA, "ping", "A:ping")
	waitRouteEcho(t, publicB, "ping", "B:ping")

	if got, err := multiAgentRoundTrip(publicA, "x", 3*time.Second); err != nil || got != "A:x" {
		t.Fatalf("route-a second round-trip: got %q err %v, want %q", got, err, "A:x")
	}
	if got, err := multiAgentRoundTrip(publicB, "y", 3*time.Second); err != nil || got != "B:y" {
		t.Fatalf("route-b second round-trip: got %q err %v, want %q", got, err, "B:y")
	}

	agents := srv.agentStatuses()
	connected := map[string]bool{}
	for _, a := range agents {
		if a.Connected {
			connected[a.ID] = true
		}
	}
	if !connected["agent-a"] || !connected["agent-b"] {
		t.Fatalf("expected agent-a and agent-b connected, got %+v", agents)
	}
}

// A route whose owner is offline refuses connections; a connected sibling still works.
func TestMultiAgentRouteOwnerOfflineRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoA, addrA := startPrefixedEcho(t, "A")
	defer echoA.Close()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicA := freeTCPAddr(t)
	publicB := freeTCPAddr(t)

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       "testtoken",
		PairTimeout: 2 * time.Second,
		DisableTLS:  true,
		Routes: []RouteConfig{
			{Name: "route-a", Proto: "tcp", PublicAddr: publicA, Agent: "agent-a"},
			{Name: "route-b", Proto: "tcp", PublicAddr: publicB, Agent: "agent-b"},
		},
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	go fakeAgentRoutesAs(ctx, controlAddr, dataAddr, "agent-a", map[string]string{"route-a": addrA}, "testtoken")
	waitRouteEcho(t, publicA, "ping", "A:ping")

	if got, err := multiAgentRoundTrip(publicB, "ping", 1*time.Second); err == nil && got == "B:ping" {
		t.Fatalf("route-b served while its owner agent-b is offline: %q", got)
	}
}

// A route with no owner is served by an agent that declares no ID (both "default").
func TestDefaultAgentOwnsUnattributedRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, echoAddr := startEcho(t)
	defer echoLn.Close()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	public := freeTCPAddr(t)

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
		Routes:      []RouteConfig{{Name: "svc", Proto: "tcp", PublicAddr: public}},
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	go fakeAgentRoutesAs(ctx, controlAddr, dataAddr, "", map[string]string{"svc": echoAddr}, "testtoken")

	waitEchoReady(t, public)
}

// UDP is tunneled to/from the route owner; data is accepted only from its address.
func TestMultiAgentUDPRoutingByOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicA := freeUDPAddr(t)
	publicB := freeUDPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
		Routes: []RouteConfig{
			{Name: "udp-a", Proto: "udp", PublicAddr: publicA, Agent: "uagent-a"},
			{Name: "udp-b", Proto: "udp", PublicAddr: publicB, Agent: "uagent-b"},
		},
	}, nil)
	go func() { _ = srv.Run(ctx) }()
	waitPublicUDPRoute(t, srv, "udp-a")
	waitPublicUDPRoute(t, srv, "udp-b")

	startFakeUDPAgentAs(t, ctx, dataAddr, "testtoken", "uagent-a", map[string]string{"udp-a": "A:"}, newTestSessionID(t), nil, nil)
	startFakeUDPAgentAs(t, ctx, dataAddr, "testtoken", "uagent-b", map[string]string{"udp-b": "B:"}, newTestSessionID(t), nil, nil)

	clientA := dialPublicUDP(t, publicA)
	defer clientA.Close()
	clientB := dialPublicUDP(t, publicB)
	defer clientB.Close()

	deadline := time.Now().Add(10 * time.Second)
	for {
		respA, errA := writeUDPAndRead(t, clientA, []byte("ping"), 1*time.Second)
		respB, errB := writeUDPAndRead(t, clientB, []byte("ping"), 1*time.Second)
		if errA == nil && errB == nil && string(respA) == "A:ping" && string(respB) == "B:ping" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("UDP not routed by owner: A=%q(%v) B=%q(%v)", respA, errA, respB, errB)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
