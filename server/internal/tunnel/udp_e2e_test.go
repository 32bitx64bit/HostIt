package tunnel

import (
	"context"
	"crypto/cipher"
	"net"
	"sync"
	"testing"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}

func waitPublicUDPRoute(t *testing.T, srv *Server, routeName string) {
	t.Helper()
	waitTunnelCondition(t, 2*time.Second, "public UDP listener was not registered for route "+routeName, func() bool {
		srv.mu.RLock()
		_, ok := srv.publicUDP[routeName]
		srv.mu.RUnlock()
		return ok
	})
}

type fakeUDPAgent struct {
	conn *net.UDPConn
	mu   sync.Mutex
	seen map[string]int
}

func startFakeUDPAgent(t *testing.T, ctx context.Context, dataAddr string, prefixes map[string]string, ciphers map[string]cipher.AEAD) *fakeUDPAgent {
	t.Helper()
	serverAddr, err := net.ResolveUDPAddr("udp", dataAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	agent := &fakeUDPAgent{conn: conn, seen: make(map[string]int)}

	sendRegister := func() {
		data, err := protocol.MarshalUDP(&protocol.Packet{Type: protocol.TypeRegister}, nil)
		if err == nil {
			_, _ = conn.WriteToUDP(data, serverAddr)
		}
	}
	sendRegister()

	go func() {
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sendRegister()
			}
		}
	}()

	go func() {
		defer conn.Close()
		buf := make([]byte, 65536)
		decryptBuf := make([]byte, 65536)
		encryptBuf := make([]byte, 65536)
		marshalBuf := make([]byte, 65536)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			pkt, err := protocol.UnmarshalUDP(buf[:n])
			if err != nil || pkt.Type != protocol.TypeData {
				continue
			}
			prefix, ok := prefixes[pkt.Route]
			if !ok {
				continue
			}

			agent.mu.Lock()
			agent.seen[pkt.Route]++
			agent.mu.Unlock()

			payload := pkt.Payload
			routeCipher := ciphers[pkt.Route]
			if routeCipher != nil {
				payload, err = crypto.DecryptUDP(routeCipher, decryptBuf, payload)
				if err != nil {
					continue
				}
			}

			responsePayload := append([]byte(prefix), payload...)
			if routeCipher != nil {
				responsePayload, err = crypto.EncryptUDP(routeCipher, encryptBuf, responsePayload)
				if err != nil {
					continue
				}
			}

			resp := &protocol.Packet{Type: protocol.TypeData, Route: pkt.Route, Client: pkt.Client, Payload: responsePayload}
			data, err := protocol.MarshalUDP(resp, marshalBuf)
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(data, serverAddr)
		}
	}()

	return agent
}

func (a *fakeUDPAgent) seenCount(route string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.seen[route]
}

func dialPublicUDP(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	conn, err := dialPublicUDPConn(addr)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func dialPublicUDPConn(addr string) (*net.UDPConn, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func writeUDPAndRead(t *testing.T, conn *net.UDPConn, payload []byte, timeout time.Duration) ([]byte, error) {
	t.Helper()
	return writeUDPAndReadConn(conn, payload, timeout)
}

func writeUDPAndReadConn(conn *net.UDPConn, payload []byte, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := conn.Write(payload); err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if err == nil {
			return append([]byte(nil), buf[:n]...), nil
		}
		lastErr = err
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			continue
		}
		return nil, err
	}
	return nil, lastErr
}

func assertNoUDPResponse(t *testing.T, conn *net.UDPConn, payload []byte, timeout time.Duration) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("unexpected UDP response %q", string(buf[:n]))
	}
}

func TestEndToEndUDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicAddr := freeUDPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      []RouteConfig{{Name: "game", Proto: "udp", PublicAddr: publicAddr}},
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()
	waitPublicUDPRoute(t, srv, "game")
	startFakeUDPAgent(t, ctx, dataAddr, map[string]string{"game": "udp:"}, nil)

	client := dialPublicUDP(t, publicAddr)
	defer client.Close()
	resp, err := writeUDPAndRead(t, client, []byte("ping"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(resp); got != "udp:ping" {
		t.Fatalf("UDP response = %q, want %q", got, "udp:ping")
	}
}

func TestEndToEndUDPConcurrentClients(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicAddr := freeUDPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes:      []RouteConfig{{Name: "game", Proto: "udp", PublicAddr: publicAddr}},
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()
	waitPublicUDPRoute(t, srv, "game")
	startFakeUDPAgent(t, ctx, dataAddr, map[string]string{"game": "udp:"}, nil)

	const clients = 12
	errCh := make(chan error, clients)
	for i := 0; i < clients; i++ {
		i := i
		go func() {
			client, err := dialPublicUDPConn(publicAddr)
			if err != nil {
				errCh <- err
				return
			}
			defer client.Close()
			payload := []byte("client-" + string(rune('a'+i)))
			resp, err := writeUDPAndReadConn(client, payload, 5*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			want := "udp:" + string(payload)
			if string(resp) != want {
				errCh <- errUnexpectedUDPResponse{got: string(resp), want: want}
				return
			}
			errCh <- nil
		}()
	}
	for i := 0; i < clients; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

type errUnexpectedUDPResponse struct {
	got  string
	want string
}

func (e errUnexpectedUDPResponse) Error() string {
	return "UDP response = " + e.got + ", want " + e.want
}

func TestEndToEndUDPMultiRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicAAddr := freeUDPAddr(t)
	publicBAddr := freeUDPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{
			{Name: "route-a", Proto: "udp", PublicAddr: publicAAddr},
			{Name: "route-b", Proto: "udp", PublicAddr: publicBAddr},
		},
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()
	waitPublicUDPRoute(t, srv, "route-a")
	waitPublicUDPRoute(t, srv, "route-b")
	startFakeUDPAgent(t, ctx, dataAddr, map[string]string{"route-a": "a:", "route-b": "b:"}, nil)

	clientA := dialPublicUDP(t, publicAAddr)
	defer clientA.Close()
	respA, err := writeUDPAndRead(t, clientA, []byte("one"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(respA); got != "a:one" {
		t.Fatalf("route-a UDP response = %q, want %q", got, "a:one")
	}

	clientB := dialPublicUDP(t, publicBAddr)
	defer clientB.Close()
	respB, err := writeUDPAndRead(t, clientB, []byte("two"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(respB); got != "b:two" {
		t.Fatalf("route-b UDP response = %q, want %q", got, "b:two")
	}
}

func TestEndToEndUDPEncrypted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key, err := crypto.DeriveKey("testtoken", crypto.AlgAES256)
	if err != nil {
		t.Fatal(err)
	}
	udpCipher, err := crypto.NewUDPCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := true
	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	publicAddr := freeUDPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr:         controlAddr,
		DataAddr:            dataAddr,
		Routes:              []RouteConfig{{Name: "game", Proto: "udp", PublicAddr: publicAddr, Encrypted: &encrypted}},
		Token:               "testtoken",
		PairTimeout:         5 * time.Second,
		DisableTLS:          true,
		EncryptionAlgorithm: crypto.AlgAES256,
	}, nil)
	go func() { _ = srv.Run(ctx) }()
	waitPublicUDPRoute(t, srv, "game")
	startFakeUDPAgent(t, ctx, dataAddr, map[string]string{"game": "secure:"}, map[string]cipher.AEAD{"game": udpCipher})

	client := dialPublicUDP(t, publicAddr)
	defer client.Close()
	resp, err := writeUDPAndRead(t, client, []byte("ping"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(resp); got != "secure:ping" {
		t.Fatalf("encrypted UDP response = %q, want %q", got, "secure:ping")
	}
}

func TestPublicUDPDropsWithoutAgentAndWhenDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	disabled := false
	controlAddr := freeTCPAddr(t)
	dataAddr := freeTCPAddr(t)
	noAgentAddr := freeUDPAddr(t)
	disabledAddr := freeUDPAddr(t)
	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Routes: []RouteConfig{
			{Name: "no-agent", Proto: "udp", PublicAddr: noAgentAddr},
			{Name: "disabled", Proto: "udp", PublicAddr: disabledAddr, Enabled: &disabled},
		},
		Token:       "testtoken",
		PairTimeout: 5 * time.Second,
		DisableTLS:  true,
	}, nil)
	go func() { _ = srv.Run(ctx) }()
	waitPublicUDPRoute(t, srv, "no-agent")
	waitPublicUDPRoute(t, srv, "disabled")

	noAgentClient := dialPublicUDP(t, noAgentAddr)
	defer noAgentClient.Close()
	assertNoUDPResponse(t, noAgentClient, []byte("drop"), 250*time.Millisecond)

	agent := startFakeUDPAgent(t, ctx, dataAddr, map[string]string{"disabled": "disabled:"}, nil)
	waitTunnelCondition(t, 2*time.Second, "fake UDP agent did not register", func() bool {
		return srv.agentUDPTime.Load() != 0
	})
	disabledClient := dialPublicUDP(t, disabledAddr)
	defer disabledClient.Close()
	assertNoUDPResponse(t, disabledClient, []byte("drop"), 250*time.Millisecond)
	if got := agent.seenCount("disabled"); got != 0 {
		t.Fatalf("disabled UDP route was forwarded to agent %d times", got)
	}
}
