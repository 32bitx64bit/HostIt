package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hostit/shared/crypto"
	"hostit/shared/protocol"
)

// fakeBenchServer is a minimal in-process server used by agent benchmarks: it
// accepts a control connection, exchanges HELLO, and on TypeConnect accepts a
// data connection, reads the route/client handshake, and pairs the local
// echo service back through it. The shape mirrors fakeTunnelServer in
// agent_integration_test.go but is parameterised on *testing.B so it can be
// used inside benchmarks.
type fakeBenchServer struct {
	controlLn   net.Listener
	dataTCPLn   net.Listener
	dataUDPConn *net.UDPConn

	controlMu    sync.Mutex
	controlConn  net.Conn
	controlReady chan struct{}

	token string
}

func startFakeBenchServer(b *testing.B, token string) *fakeBenchServer {
	b.Helper()
	for attempt := 0; attempt < 50; attempt++ {
		controlLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		controlPort := controlLn.Addr().(*net.TCPAddr).Port
		dataAddr := net.JoinHostPort("127.0.0.1", itoa(controlPort+1))

		dataTCPLn, err := net.Listen("tcp", dataAddr)
		if err != nil {
			_ = controlLn.Close()
			continue
		}
		udpAddr, err := net.ResolveUDPAddr("udp", dataAddr)
		if err != nil {
			_ = dataTCPLn.Close()
			_ = controlLn.Close()
			continue
		}
		dataUDPConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			_ = dataTCPLn.Close()
			_ = controlLn.Close()
			continue
		}
		s := &fakeBenchServer{
			controlLn:    controlLn,
			dataTCPLn:    dataTCPLn,
			dataUDPConn:  dataUDPConn,
			controlReady: make(chan struct{}),
			token:        token,
		}
		go s.acceptControl()
		return s
	}
	b.Fatal("failed to allocate fake control/data listeners")
	return nil
}

func (s *fakeBenchServer) close() {
	s.controlMu.Lock()
	if s.controlConn != nil {
		_ = s.controlConn.Close()
	}
	s.controlMu.Unlock()
	if s.dataUDPConn != nil {
		_ = s.dataUDPConn.Close()
	}
	if s.dataTCPLn != nil {
		_ = s.dataTCPLn.Close()
	}
	if s.controlLn != nil {
		_ = s.controlLn.Close()
	}
}

func (s *fakeBenchServer) serverAddr() string { return s.controlLn.Addr().String() }

func (s *fakeBenchServer) acceptControl() {
	conn, err := s.controlLn.Accept()
	if err != nil {
		close(s.controlReady)
		return
	}
	if _, _, err := crypto.AuthenticateServer(conn, s.token); err != nil {
		_ = conn.Close()
		close(s.controlReady)
		return
	}

	pkt, err := protocol.ReadPacket(conn)
	if err != nil || pkt.Type != protocol.TypeVersionNegotiate {
		_ = conn.Close()
		close(s.controlReady)
		return
	}
	verPayload, _ := json.Marshal(protocol.VersionPayload{Version: protocol.ProtocolVersion})
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeVersionNegotiate, Payload: verPayload}); err != nil {
		_ = conn.Close()
		close(s.controlReady)
		return
	}

	s.controlMu.Lock()
	s.controlConn = conn
	s.controlMu.Unlock()
	close(s.controlReady)
}

func (s *fakeBenchServer) waitControl(b *testing.B) net.Conn {
	b.Helper()
	select {
	case <-s.controlReady:
	case <-time.After(5 * time.Second):
		b.Fatal("timed out waiting for control connection")
	}
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	return s.controlConn
}

func (s *fakeBenchServer) sendHello(b *testing.B, routes map[string]RemoteRoute) {
	b.Helper()
	conn := s.waitControl(b)
	hello := helloPayload{Routes: routes}
	payload, err := json.Marshal(hello)
	if err != nil {
		b.Fatal(err)
	}
	if err := protocol.WritePacket(conn, &protocol.Packet{Type: protocol.TypeHello, Payload: payload}); err != nil {
		b.Fatal(err)
	}
}

func startBenchEcho(b *testing.B) (net.Listener, string) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln, ln.Addr().String()
}

// waitForBenchAgentReady and friends are intentionally absent: benchmarks
// drive the agent directly via sendHello + waitControl, so any helper would
// just add indirection.

// BenchmarkAgentEndToEnd measures the full agent round-trip: control handshake,
// data connect, local dial, and relay.
func BenchmarkAgentEndToEnd(b *testing.B) {
	sizes := []int{1 << 10, 4 << 10, 32 << 10}
	for _, size := range sizes {
		b.Run(payloadLabel(size), func(b *testing.B) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			echoLn, echoAddr := startBenchEcho(b)
			defer echoLn.Close()

			server := startFakeBenchServer(b, "benchtoken")
			defer server.close()

			connectedCh := make(chan struct{}, 1)
			agentDone := make(chan struct{})
			go func() {
				defer close(agentDone)
				_ = RunWithHooks(ctx, Config{
					Server:     server.serverAddr(),
					Token:      "benchtoken",
					DisableTLS: true,
				}, &Hooks{OnConnected: func() {
					select {
					case connectedCh <- struct{}{}:
					default:
					}
				}})
			}()
			defer func() {
				cancel()
				<-agentDone
			}()

			server.sendHello(b, map[string]RemoteRoute{
				"default": {Name: "default", Proto: "tcp", LocalAddr: echoAddr, PublicAddr: ":0"},
			})
			select {
			case <-connectedCh:
			case <-time.After(5 * time.Second):
				b.Fatal("agent never connected")
			}

			control := server.waitControl(b)

			payload := make([]byte, size)
			if _, err := rand.Read(payload); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(size) * 2)
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				if err := protocol.WritePacket(control, &protocol.Packet{
					Type: protocol.TypeConnect, Route: "default", Client: "c",
				}); err != nil {
					b.Fatal(err)
				}
				dataConn, _, _ := server.acceptDataConnBench(b)
				defer dataConn.Close()

				_ = dataConn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := dataConn.Write(payload); err != nil {
					b.Fatal(err)
				}
				got := make([]byte, size)
				if _, err := io.ReadFull(dataConn, got); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAgentControlPlane measures the steady-state cost of a single
// control-packet read/parse cycle.
func BenchmarkAgentControlPlane(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := startFakeBenchServer(b, "benchtoken")
	defer server.close()

	connectedCh := make(chan struct{}, 1)
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		_ = RunWithHooks(ctx, Config{
			Server:     server.serverAddr(),
			Token:      "benchtoken",
			DisableTLS: true,
		}, &Hooks{OnConnected: func() {
			select {
			case connectedCh <- struct{}{}:
			default:
			}
		}})
	}()
	defer func() {
		cancel()
		<-agentDone
	}()

	server.sendHello(b, nil)
	select {
	case <-connectedCh:
	case <-time.After(5 * time.Second):
		b.Fatal("agent never connected")
	}

	control := server.waitControl(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := protocol.WritePacket(control, &protocol.Packet{Type: protocol.TypePing, Payload: []byte{0}}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAgentConcurrentConnections measures per-connection relay throughput
// with many parallel public clients.
func BenchmarkAgentConcurrentConnections(b *testing.B) {
	const (
		payloadSize = 32 * 1024
		concurrency = 16
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, echoAddr := startBenchEcho(b)
	defer echoLn.Close()

	server := startFakeBenchServer(b, "benchtoken")
	defer server.close()

	connectedCh := make(chan struct{}, 1)
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		_ = RunWithHooks(ctx, Config{
			Server:     server.serverAddr(),
			Token:      "benchtoken",
			DisableTLS: true,
		}, &Hooks{OnConnected: func() {
			select {
			case connectedCh <- struct{}{}:
			default:
			}
		}})
	}()
	defer func() {
		cancel()
		<-agentDone
	}()

	server.sendHello(b, map[string]RemoteRoute{
		"default": {Name: "default", Proto: "tcp", LocalAddr: echoAddr, PublicAddr: ":0"},
	})
	select {
	case <-connectedCh:
	case <-time.After(5 * time.Second):
		b.Fatal("agent never connected")
	}

	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(payloadSize) * 2 * concurrency)
	b.ReportAllocs()
	b.ResetTimer()

	var failures atomic.Int64
	for i := 0; i < b.N; i++ {
		control := server.waitControl(b)
		var wg sync.WaitGroup
		for c := 0; c < concurrency; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := protocol.WritePacket(control, &protocol.Packet{
					Type: protocol.TypeConnect, Route: "default", Client: "c",
				}); err != nil {
					failures.Add(1)
					return
				}
				dataConn, _, _ := server.acceptDataConnBench(b)
				defer dataConn.Close()
				_ = dataConn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := dataConn.Write(payload); err != nil {
					failures.Add(1)
					return
				}
				got := make([]byte, payloadSize)
				if _, err := io.ReadFull(dataConn, got); err != nil {
					failures.Add(1)
					return
				}
			}()
		}
		wg.Wait()
	}
	if failures.Load() > 0 {
		b.Fatalf("%d concurrent agent round-trips failed", failures.Load())
	}
}

func (s *fakeBenchServer) acceptDataConnBench(b *testing.B) (net.Conn, string, string) {
	b.Helper()
	if err := s.dataTCPLn.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		b.Fatal(err)
	}
	conn, err := s.dataTCPLn.Accept()
	if err != nil {
		b.Fatal(err)
	}
	if _, _, err := crypto.AuthenticateServer(conn, s.token); err != nil {
		_ = conn.Close()
		b.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = conn.Close()
		b.Fatal(err)
	}
	var routeLen byte
	if err := binary.Read(conn, binary.BigEndian, &routeLen); err != nil {
		_ = conn.Close()
		b.Fatal(err)
	}
	routeBytes := make([]byte, int(routeLen))
	if _, err := io.ReadFull(conn, routeBytes); err != nil {
		_ = conn.Close()
		b.Fatal(err)
	}
	var clientLen byte
	if err := binary.Read(conn, binary.BigEndian, &clientLen); err != nil {
		_ = conn.Close()
		b.Fatal(err)
	}
	clientBytes := make([]byte, int(clientLen))
	if _, err := io.ReadFull(conn, clientBytes); err != nil {
		_ = conn.Close()
		b.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn, string(routeBytes), string(clientBytes)
}

func payloadLabel(n int) string {
	if n >= (1 << 10) {
		return itoa(n>>10) + "KB"
	}
	return itoa(n) + "B"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
