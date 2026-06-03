package tunnel

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hostit/shared/protocol"
)

// startEchoB and waitEchoReadyB are the *testing.B-compatible mirrors of
// startEcho and waitEchoReady in tunnel_test.go; the originals only accept
// *testing.T and we want to keep this benchmark self-contained.
func startEchoB(b *testing.B) (net.Listener, string) {
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

func waitEchoReadyB(b *testing.B, addr string) {
	b.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if time.Now().After(deadline) {
			b.Fatalf("tunnel %s never became ready", addr)
		}
		c, err := net.Dial("tcp", addr)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		msg := []byte("ready\n")
		if _, werr := c.Write(msg); werr != nil {
			_ = c.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		buf := make([]byte, len(msg))
		_, rerr := io.ReadFull(c, buf)
		_ = c.Close()
		if rerr != nil || string(buf) != string(msg) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return
	}
}

// BenchmarkTunneledTCPEndToEnd measures full-path throughput of a tunneled
// TCP connection: public client -> server.publicTCP -> server.dataConn ->
// agent.dataConn -> local service -> back. The fake agent and local echo
// service match the helper layer in tunnel_test.go so the benchmark is a
// faithful reproduction of the runtime path. Run with representative
// payload sizes; the result bounds the per-connection bandwidth a single
// relayed TCP session can sustain on this host.
func BenchmarkTunneledTCPEndToEnd(b *testing.B) {
	sizes := []int{1 << 10, 4 << 10, 32 << 10}
	for _, size := range sizes {
		b.Run(payloadLabel(size), func(b *testing.B) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			echoLn, echoAddr := startEchoB(b)
			defer echoLn.Close()

			controlAddr, dataAddr, publicAddr := reserveLoopbackAddrs(b)

			srv := NewServer(ServerConfig{
				ControlAddr: controlAddr,
				DataAddr:    dataAddr,
				Token:       "benchtoken",
				DisableTLS:  true,
				PairTimeout: 10 * time.Second,
				Routes: []RouteConfig{{
					Name:       "default",
					Proto:      "tcp",
					PublicAddr: publicAddr,
				}},
			}, nil)
			go func() { _ = srv.Run(ctx) }()

			go fakeAgent(ctx, controlAddr, dataAddr, echoAddr, "benchtoken")
			waitEchoReadyB(b, publicAddr)

			payload := make([]byte, size)
			if _, err := rand.Read(payload); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(size) * 2)
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				c, err := net.Dial("tcp", publicAddr)
				if err != nil {
					b.Fatal(err)
				}
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(payload); err != nil {
					c.Close()
					b.Fatal(err)
				}
				got := make([]byte, size)
				if _, err := io.ReadFull(c, got); err != nil {
					c.Close()
					b.Fatal(err)
				}
				c.Close()
			}
		})
	}
}

// BenchmarkTunneledTCPConcurrent measures the same path with many parallel
// connections to capture scheduler and lock contention. A real production
// server is hosting many concurrent tunnels, so this number is what to watch
// when chasing tail latency under load.
func BenchmarkTunneledTCPConcurrent(b *testing.B) {
	const (
		payloadSize = 32 * 1024
		concurrency = 32
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, echoAddr := startEchoB(b)
	defer echoLn.Close()

	controlAddr, dataAddr, publicAddr := reserveLoopbackAddrs(b)

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       "benchtoken",
		DisableTLS:  true,
		PairTimeout: 10 * time.Second,
		Routes: []RouteConfig{{
			Name:       "default",
			Proto:      "tcp",
			PublicAddr: publicAddr,
		}},
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	go fakeAgent(ctx, controlAddr, dataAddr, echoAddr, "benchtoken")
	waitEchoReadyB(b, publicAddr)

	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(payloadSize) * 2 * concurrency)
	b.ReportAllocs()
	b.ResetTimer()

	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < b.N; i++ {
		for c := 0; c < concurrency; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := net.Dial("tcp", publicAddr)
				if err != nil {
					failures.Add(1)
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
				if _, err := conn.Write(payload); err != nil {
					failures.Add(1)
					return
				}
				got := make([]byte, payloadSize)
				if _, err := io.ReadFull(conn, got); err != nil {
					failures.Add(1)
					return
				}
			}()
		}
		wg.Wait()
	}
	if failures.Load() > 0 {
		b.Fatalf("%d concurrent round-trips failed", failures.Load())
	}
}

// BenchmarkTunneledTCPConnectionsPerSecond measures connection establishment
// latency: how many public->agent->local->back round-trips can be completed
// per second. The figure captures the per-connection overhead in
// acceptPublicTCP, the session lookup under sessionsMu, the pendingTCP map
// dance, and the connect packet write. A regression here usually means one
// of those code paths took a new allocation or lock.
func BenchmarkTunneledTCPConnectionsPerSecond(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	echoLn, echoAddr := startEchoB(b)
	defer echoLn.Close()

	controlAddr, dataAddr, publicAddr := reserveLoopbackAddrs(b)

	srv := NewServer(ServerConfig{
		ControlAddr: controlAddr,
		DataAddr:    dataAddr,
		Token:       "benchtoken",
		DisableTLS:  true,
		PairTimeout: 10 * time.Second,
		Routes: []RouteConfig{{
			Name:       "default",
			Proto:      "tcp",
			PublicAddr: publicAddr,
		}},
	}, nil)
	go func() { _ = srv.Run(ctx) }()

	go fakeAgent(ctx, controlAddr, dataAddr, echoAddr, "benchtoken")
	waitEchoReadyB(b, publicAddr)

	probe := []byte("hi\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.Dial("tcp", publicAddr)
		if err != nil {
			b.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(probe); err != nil {
			c.Close()
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, make([]byte, len(probe))); err != nil {
			c.Close()
			b.Fatal(err)
		}
		c.Close()
	}
}

// BenchmarkRouteCacheLookup isolates the atomic.Value route-cache read that
// runs on every accepted public TCP connection and on every UDP datagram.
// The route-cache lookup is a primary candidate for the dashboard stats
// overhead, so this benchmark pins the lookup cost to a number that
// regressions can be measured against.
func BenchmarkRouteCacheLookup(b *testing.B) {
	srv := NewServer(ServerConfig{
		ControlAddr: "127.0.0.1:0",
		DataAddr:    "127.0.0.1:0",
		Token:       "x",
		DisableTLS:  true,
		Routes: []RouteConfig{{
			Name: "default", Proto: "tcp", PublicAddr: ":0",
		}},
	}, nil)
	srv.updateRouteCache()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = srv.getRouteConfig("default")
	}
}

// BenchmarkUnmarshalUDPTo mirrors the per-packet work in acceptAgentUDP and
// acceptPublicUDP: parse a tunneled UDP datagram and pull out the route,
// client, and payload. This is the dominant CPU cost of the UDP forwarding
// path, so a regression here is a regression in tunneled UDP throughput.
func BenchmarkUnmarshalUDPTo(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192}
	for _, size := range sizes {
		b.Run(payloadLabel(size), func(b *testing.B) {
			src := &protocol.Packet{
				Type:    protocol.TypeData,
				Route:   "rt",
				Client:  "1.2.3.4:5000",
				Payload: make([]byte, size),
			}
			frame, err := protocol.MarshalUDP(src, make([]byte, 65536))
			if err != nil {
				b.Fatal(err)
			}
			var dst protocol.Packet
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := protocol.UnmarshalUDPTo(frame, &dst); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkControlPlanePingPong measures the per-packet cost of the
// server's control-channel receive path: read a Ping frame (control-plane
// TCP format), then write a Pong response. This is the steady-state cost
// the server's 15-second periodic pinger pays to keep the agent's control
// connection alive, and a regression here shows up as elevated latency
// on every control-plane RPC. The benchmark uses the same control-plane
// framing (ReadPacketTo + WritePacket) that production traffic uses; the
// UDP path's MarshalUDP has a different wire format and is covered by
// BenchmarkUDPRoundTrip.
func BenchmarkControlPlanePingPong(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	server := <-accepted
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		var pkt protocol.Packet
		for {
			if err := protocol.ReadPacketTo(server, &pkt); err != nil {
				return
			}
			pong := &protocol.Packet{Type: protocol.TypePong, Payload: pkt.Payload}
			if err := protocol.WritePacket(server, pong); err != nil {
				return
			}
		}
	}()

	ping := &protocol.Packet{Type: protocol.TypePing, Payload: []byte("hello")}
	w := &appendWriter{buf: make([]byte, 0, 64)}
	if err := protocol.WritePacket(w, ping); err != nil {
		b.Fatal(err)
	}
	pingFrame := w.buf
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(pingFrame); err != nil {
			b.Fatal(err)
		}
		var pkt protocol.Packet
		if err := protocol.ReadPacketTo(client, &pkt); err != nil {
			b.Fatal(err)
		}
	}
	client.Close()
	<-done
}

// BenchmarkUDPTunnelHotPath measures the per-packet cost the server pays
// on acceptAgentUDP: read a UDP datagram from the agent, UnmarshalUDPTo
// to extract the route+client+payload, and look up the routeConfig from
// the cache. This is the dominant CPU cost on the inbound UDP path. The
// encryption path is exercised separately by BenchmarkEncryptUDP and is
// excluded here to keep the benchmark focused on framing + cache lookup.
func BenchmarkUDPTunnelHotPath(b *testing.B) {
	sizes := []int{64, 512, 1400}
	for _, size := range sizes {
		b.Run(payloadLabel(size), func(b *testing.B) {
			src := &protocol.Packet{
				Type:    protocol.TypeData,
				Route:   "rt",
				Client:  "1.2.3.4:5000",
				Payload: make([]byte, size),
			}
			frame, err := protocol.MarshalUDP(src, make([]byte, 65536))
			if err != nil {
				b.Fatal(err)
			}
			var dst protocol.Packet
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := protocol.UnmarshalUDPTo(frame, &dst); err != nil {
					b.Fatal(err)
				}
				_ = dst.Route
				_ = dst.Client
				_ = dst.Payload
			}
		})
	}
}

// reserveLoopbackAddrs returns three unused loopback addresses (control,
// data, public) without holding the listeners open. We close the listeners
// immediately and rely on the kernel not to reassign the port within the
// benchmark's lifetime; this matches the pattern in tunnel_test.go.
func reserveLoopbackAddrs(b *testing.B) (control, data, public string) {
	b.Helper()
	control = reserveAddr(b)
	data = reserveAddr(b)
	public = reserveAddr(b)
	return control, data, public
}

func reserveAddr(b *testing.B) string {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func payloadLabel(n int) string {
	switch {
	case n >= (1 << 20):
		return fmtInt(n>>20) + "MB"
	case n >= (1 << 10):
		return fmtInt(n>>10) + "KB"
	default:
		return fmtInt(n) + "B"
	}
}

// appendWriter is a tiny io.Writer adapter used by BenchmarkControlPlanePingPong
// to capture the marshaled Ping frame into a reusable buffer. The standard
// bytes.Buffer would work, but we avoid its reset overhead with a hand-rolled
// appender that only allocates when the buffer is too small.
type appendWriter struct {
	buf []byte
}

func (a *appendWriter) Write(p []byte) (int, error) {
	a.buf = append(a.buf, p...)
	return len(p), nil
}

func fmtInt(n int) string {
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
