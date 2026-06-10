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
// TCP connection at various payload sizes.
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

// BenchmarkTunneledTCPConcurrent measures throughput under many parallel
// connections to capture scheduler and lock contention.
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
// latency (round-trips per second). A regression here usually means new
// allocation or lock contention in the pairing path.
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

// BenchmarkRouteCacheLookup isolates the per-request route-cache read.
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

// BenchmarkUnmarshalUDPTo measures the per-packet unmarshaling cost of the
// UDP forwarding path.
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
// control-channel Ping/Pong path.
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

// BenchmarkUDPTunnelHotPath measures the per-packet inbound UDP cost
// (framing + cache lookup), excluding encryption.
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
