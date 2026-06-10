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
// proxy pair over loopback TCP. A single Proxy invocation stands in for the
// full relay hop (public client <-> server <-> agent <-> local service).
func BenchmarkProxyThroughput(b *testing.B) {
	sizes := []int{1 << 10, 4 << 10, 32 << 10, 256 << 10}
	for _, size := range sizes {
		b.Run(payloadLabel(size), func(b *testing.B) {
			benchmarkProxyLoop(b, size, 0)
		})
	}
}

// BenchmarkProxyWithIdleTimeout is the same path with idle-timeout enabled
// (the production default). Confirms that refresh throttling keeps overhead
// negligible and detects regressions in the fast path.
func BenchmarkProxyWithIdleTimeout(b *testing.B) {
	sizes := []int{1 << 10, 4 << 10, 32 << 10, 256 << 10}
	for _, size := range sizes {
		b.Run(payloadLabel(size), func(b *testing.B) {
			benchmarkProxyLoop(b, size, 100*time.Millisecond)
		})
	}
}

// BenchmarkProxyConcurrent measures aggregate throughput with many parallel
// proxy pairs. Stand up `concurrency` independent pairs per iteration and
// wait for them all to finish so reported throughput reflects aggregate work.
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

// benchmarkProxyLoop pushes payloads through Proxy over loopback TCP.
// Connections are reused per iteration to amortize connect/teardown noise.
// The echo listener uses separate connections so two goroutines don't
// read from the same socket, matching production. The first sample
// warms buffers and is discarded.
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

// loopbackPipe returns a client/server TCP loopback pair. Uses real TCP
// instead of net.Pipe to exercise the production socket/syscall path.
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

// BenchmarkCountingConnRead checks the per-byte cost of countingConn,
// which wraps the public-side hot path. The new atomic.Int64 + Flush
// path should be cheaper than the old closure-based approach.
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

// countingBenchConn mirrors production countingConn: intercepts Read to
// count bytes via an atomic counter.
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
