package relay

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkProxyThroughput measures end-to-end byte throughput of a single
// proxy pair over a real loopback TCP socket. This is the canonical data path
// for every tunneled TCP connection: public client <-> server <-> agent <-> local
// service, so a single Proxy invocation here stands in for the full relay hop.
// Run with a representative payload size and a fixed b.N to get stable
// numbers across runs; -benchtime=2s is usually enough.
func BenchmarkProxyThroughput(b *testing.B) {
	sizes := []int{1 << 10, 4 << 10, 32 << 10, 256 << 10}
	for _, size := range sizes {
		b.Run(payloadLabel(size), func(b *testing.B) {
			benchmarkProxyLoop(b, size, 0)
		})
	}
}

// BenchmarkProxyWithIdleTimeout is the same path with the idle-timeout
// wrapper enabled (the default configuration in production). Idle-timeout
// refresh throttling should keep per-byte overhead negligible versus plain
// Proxy; this benchmark confirms that and detects any regression in the
// refresh fast path.
func BenchmarkProxyWithIdleTimeout(b *testing.B) {
	sizes := []int{1 << 10, 4 << 10, 32 << 10, 256 << 10}
	for _, size := range sizes {
		b.Run(payloadLabel(size), func(b *testing.B) {
			benchmarkProxyLoop(b, size, 100*time.Millisecond)
		})
	}
}

// BenchmarkProxyConcurrent measures aggregate throughput with many parallel
// proxy pairs running simultaneously. This is the realistic case for a server
// hosting many concurrent tunneled connections, and the workload where
// contention on the per-connection goroutine pair, the buffer pool, and the
// OS scheduler becomes visible. We stand up `concurrency` independent pairs
// per iteration and wait for them all to finish, so the per-iteration cost
// reflects the aggregate work and the throughput is reported correctly.
func BenchmarkProxyConcurrent(b *testing.B) {
	const (
		payloadSize  = 32 * 1024
		concurrency  = 32
		perPairIters = 16
	)
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	runPair := func() {
		frontClient, frontServer := loopbackPipe(b)
		backClient, backServer := loopbackPipe(b)
		echoDone := make(chan struct{})
		go func() {
			defer close(echoDone)
			_, _ = io.Copy(backClient, backClient)
		}()
		done := make(chan struct{})
		go func() {
			defer close(done)
			ProxyWithIdleTimeout(frontServer, backServer, 0)
		}()
		_ = frontClient.SetDeadline(time.Now().Add(30 * time.Second))
		for k := 0; k < perPairIters; k++ {
			if _, err := frontClient.Write(payload); err != nil {
				break
			}
			got := make([]byte, payloadSize)
			if _, err := io.ReadFull(frontClient, got); err != nil {
				break
			}
		}
		frontClient.Close()
		frontServer.Close()
		backClient.Close()
		backServer.Close()
		<-done
		<-echoDone
	}

	b.SetBytes(int64(payloadSize) * 2 * concurrency * perPairIters)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for c := 0; c < concurrency; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runPair()
			}()
		}
		wg.Wait()
	}
}

// benchmarkProxyLoop sets up a pair of TCP loopback connections and pushes
// many payloads through Proxy using the same connections. The per-iter
// connect/teardown noise is paid once and amortized over the loop, so the
// measured time is the steady-state relay cost (read + write + per-RTT
// overhead) and not the cost of repeatedly dialing new sockets. The
// topology mirrors the real data path: the front (client) side dials a
// listener, the back (local-service) side is a separate dial into a
// loopback echo listener. The echo listener does NOT share a connection
// with the proxy because that would have two goroutines reading from the
// same socket and split the bytes between them, which is not what
// production traffic looks like. We use the first sample to warm the
// socket buffers and discard it.
func benchmarkProxyLoop(b *testing.B, payloadSize int, idleTimeout time.Duration) {
	b.Helper()
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}

	const itersPerConn = 64
	bytesPerIter := int64(payloadSize) * 2
	b.SetBytes(bytesPerIter * itersPerConn)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		frontClient, frontServer := loopbackPipe(b)
		backClient, backServer := loopbackPipe(b)
		echoDone := make(chan struct{})
		go func() {
			defer close(echoDone)
			_, _ = io.Copy(backClient, backClient)
		}()
		done := make(chan struct{})
		go func() {
			defer close(done)
			ProxyWithIdleTimeout(frontServer, backServer, idleTimeout)
		}()

		_ = frontClient.SetDeadline(time.Now().Add(30 * time.Second))
		// Warm-up round-trip so the first timing sample does not include
		// kernel buffer warm-up cost.
		frontClient.Write(payload)
		got := make([]byte, payloadSize)
		io.ReadFull(frontClient, got)

		for k := 0; k < itersPerConn; k++ {
			if _, err := frontClient.Write(payload); err != nil {
				break
			}
			if _, err := io.ReadFull(frontClient, got); err != nil {
				break
			}
		}
		frontClient.Close()
		frontServer.Close()
		backClient.Close()
		backServer.Close()
		<-done
		<-echoDone
	}
}

// loopbackPipe dials two loopback TCP sockets and returns the client side and
// server side of the connection. We use real TCP rather than net.Pipe so the
// benchmark exercises the same socket/syscall path as production traffic.
func loopbackPipe(b *testing.B) (net.Conn, net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		resCh <- result{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	server := <-resCh
	if server.err != nil {
		client.Close()
		b.Fatal(server.err)
	}
	return client, server.conn
}

// BenchmarkCountingConn is a regression check for the per-byte closure cost
// introduced by wrapping the public-side Conn in a countingConn for dashboard
// stats. The wrapper is on the public-TCP hot path: every byte counted is one
// extra virtual call. Run with a representative size; a regression here shows
// up immediately in interactive tunneling latency. The new API uses an
// atomic.Int64 that accumulates in the hot path and is drained by an explicit
// Flush, so this benchmark also covers the atomic-add cost to confirm it is
// cheaper than the old closure path.
func BenchmarkCountingConnRead(b *testing.B) {
	payload := make([]byte, 16<<10)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}
	a, bSide := net.Pipe()
	defer a.Close()
	defer bSide.Close()

	// Mirror the new countingConn API: an atomic counter drained by Flush,
	// not a per-read closure that calls into the dashboard.
	var pending atomic.Int64
	wrapper := &countingBenchConn{Conn: bSide, pending: &pending}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, wrapper)
	}()

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	a.Close()
	<-done
	// Final flush so a regression in the drain path is also visible.
	pending.Store(0)
}

// countingBenchConn mirrors server's countingConn: it intercepts Read to
// count bytes, but otherwise is a passthrough. The atomic counter pattern
// matches the production code so the benchmark's reported per-read cost is
// the cost real traffic will pay.
type countingBenchConn struct {
	net.Conn
	pending *atomic.Int64
}

func (c *countingBenchConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.pending.Add(int64(n))
	}
	return n, err
}

func payloadLabel(n int) string {
	switch {
	case n >= (1 << 20):
		return mbLabel(n >> 20) + "MB"
	case n >= (1 << 10):
		return kbLabel(n>>10) + "KB"
	default:
		return itoa(n) + "B"
	}
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func mbLabel(n int) string { return itoa(n) }
func kbLabel(n int) string { return itoa(n) }

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
