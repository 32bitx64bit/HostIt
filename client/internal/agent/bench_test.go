package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// BenchmarkCopyOptimized measures the throughput of the bidirectional copy function
func BenchmarkCopyOptimized(b *testing.B) {
	sizes := []int{
		1024,           // 1KB
		16 * 1024,      // 16KB
		64 * 1024,      // 64KB
		256 * 1024,     // 256KB
		1024 * 1024,    // 1MB
		10 * 1024 * 1024, // 10MB
	}

	for _, size := range sizes {
		b.Run(bytesToHuman(size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				src := bytes.NewReader(data)
				dst := io.Discard
				copyOptimized(dst, src)
			}
		})
	}
}

// BenchmarkBidirPipe measures bidirectional pipe throughput using in-memory connections
func BenchmarkBidirPipe(b *testing.B) {
	sizes := []int{
		64 * 1024,      // 64KB
		256 * 1024,     // 256KB
		1024 * 1024,    // 1MB
		10 * 1024 * 1024, // 10MB
	}

	for _, size := range sizes {
		b.Run(bytesToHuman(size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.SetBytes(int64(size * 2)) // bidirectional
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				clientA, serverA := net.Pipe()
				clientB, serverB := net.Pipe()

				var wg sync.WaitGroup
				wg.Add(3)

				// Sender A -> B
				go func() {
					defer wg.Done()
					clientA.Write(data)
					clientA.Close()
				}()

				// Sender B -> A
				go func() {
					defer wg.Done()
					clientB.Write(data)
					clientB.Close()
				}()

				// Bidirectional pipe
				go func() {
					defer wg.Done()
					bidirPipe(serverA, serverB)
				}()

				wg.Wait()
			}
		})
	}
}

// BenchmarkTCPThroughput measures actual TCP throughput over loopback
func BenchmarkTCPThroughput(b *testing.B) {
	sizes := []int{
		64 * 1024,       // 64KB
		1024 * 1024,     // 1MB
		10 * 1024 * 1024, // 10MB
		100 * 1024 * 1024, // 100MB
	}

	for _, size := range sizes {
		b.Run(bytesToHuman(size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer ln.Close()

			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				wg.Add(2)

				// Server: accept and read
				go func() {
					defer wg.Done()
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					io.Copy(io.Discard, conn)
				}()

				// Client: connect and write
				go func() {
					defer wg.Done()
					conn, err := net.Dial("tcp", ln.Addr().String())
					if err != nil {
						return
					}
					defer conn.Close()
					conn.Write(data)
				}()

				wg.Wait()
			}
		})
	}
}

// BenchmarkConnectionPool measures pool get/return performance
func BenchmarkConnectionPool(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a mock server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Keep connection open
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				for {
					_, err := c.Read(buf)
					if err != nil {
						c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	pool := &dataConnPool{
		addr:     ln.Addr().String(),
		useTLS:   false,
		noDelay:  true,
		ch:       make(chan net.Conn, 10),
		capacity: 10,
	}

	cfg := Config{}

	// Warm up pool
	pool.warmup(ctx, cfg, 10)

	b.ResetTimer()

	b.Run("TryGet", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if c := pool.tryGet(); c != nil {
				// Return to pool
				select {
				case pool.ch <- c:
					pool.size.Add(1)
				default:
					c.Close()
				}
			}
		}
	})

	b.Run("GetOrDial", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			c, err := pool.getOrDial(ctx, cfg)
			if err != nil {
				b.Fatal(err)
			}
			// Return to pool
			select {
			case pool.ch <- c:
				pool.size.Add(1)
			default:
				c.Close()
			}
		}
	})
}

// BenchmarkBufferPoolAlloc compares pool vs direct allocation
func BenchmarkBufferPoolAlloc(b *testing.B) {
	b.Run("Pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := copyBufPool.Get().([]byte)
			_ = buf[0] // Use buffer
			copyBufPool.Put(buf)
		}
	})

	b.Run("DirectAlloc", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := make([]byte, 512*1024)
			_ = buf[0] // Use buffer
		}
	})
}

// BenchmarkTCPWithOptions measures impact of TCP options
func BenchmarkTCPWithOptions(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	rand.Read(data)

	benchWithOptions := func(b *testing.B, noDelay bool, bufSize int) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		defer ln.Close()

		b.SetBytes(int64(len(data)))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetNoDelay(noDelay)
					if bufSize > 0 {
						tc.SetReadBuffer(bufSize)
						tc.SetWriteBuffer(bufSize)
					}
				}
				io.Copy(io.Discard, conn)
			}()

			go func() {
				defer wg.Done()
				conn, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					return
				}
				defer conn.Close()
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetNoDelay(noDelay)
					if bufSize > 0 {
						tc.SetReadBuffer(bufSize)
						tc.SetWriteBuffer(bufSize)
					}
				}
				conn.Write(data)
			}()

			wg.Wait()
		}
	}

	b.Run("Default", func(b *testing.B) {
		benchWithOptions(b, false, 0)
	})

	b.Run("NoDelay", func(b *testing.B) {
		benchWithOptions(b, true, 0)
	})

	b.Run("NoDelay+64KB", func(b *testing.B) {
		benchWithOptions(b, true, 64*1024)
	})

	b.Run("NoDelay+256KB", func(b *testing.B) {
		benchWithOptions(b, true, 256*1024)
	})

	b.Run("NoDelay+512KB", func(b *testing.B) {
		benchWithOptions(b, true, 512*1024)
	})
}

// BenchmarkLatency measures connection establishment latency
func BenchmarkLatency(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	// Accept in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	b.Run("TCPConnect", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			conn.Close()
		}
	})

	b.Run("TCPConnectWithOptions", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			d := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
			conn, err := d.Dial("tcp", ln.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
				tc.SetReadBuffer(256 * 1024)
				tc.SetWriteBuffer(256 * 1024)
			}
			conn.Close()
		}
	})
}

// TestThroughputReport generates a human-readable throughput report
func TestThroughputReport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping throughput report in short mode")
	}

	sizes := []int{
		64 * 1024,
		256 * 1024,
		1024 * 1024,
		10 * 1024 * 1024,
	}

	t.Log("=== Throughput Report ===")

	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)

		// Create TCP server
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}

		iterations := 10
		var totalDuration time.Duration

		for i := 0; i < iterations; i++ {
			var wg sync.WaitGroup
			wg.Add(2)

			start := time.Now()

			go func() {
				defer wg.Done()
				conn, _ := ln.Accept()
				if conn != nil {
					defer conn.Close()
					if tc, ok := conn.(*net.TCPConn); ok {
						tc.SetNoDelay(true)
						tc.SetReadBuffer(256 * 1024)
						tc.SetWriteBuffer(256 * 1024)
					}
					io.Copy(io.Discard, conn)
				}
			}()

			go func() {
				defer wg.Done()
				conn, _ := net.Dial("tcp", ln.Addr().String())
				if conn != nil {
					defer conn.Close()
					if tc, ok := conn.(*net.TCPConn); ok {
						tc.SetNoDelay(true)
						tc.SetReadBuffer(256 * 1024)
						tc.SetWriteBuffer(256 * 1024)
					}
					conn.Write(data)
				}
			}()

			wg.Wait()
			totalDuration += time.Since(start)
		}

		ln.Close()

		avgDuration := totalDuration / time.Duration(iterations)
		throughput := float64(size) / avgDuration.Seconds() / (1024 * 1024)

		t.Logf("Size: %s, Avg Duration: %v, Throughput: %.2f MB/s",
			bytesToHuman(size), avgDuration, throughput)
	}
}

// TestBidirPipeThroughput tests bidirectional throughput
func TestBidirPipeThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping throughput test in short mode")
	}

	size := 10 * 1024 * 1024 // 10MB each direction
	data := make([]byte, size)
	rand.Read(data)

	iterations := 5
	var totalDuration time.Duration
	var totalBytes int64

	for i := 0; i < iterations; i++ {
		// Use net.Pipe for simpler bidirectional test
		clientA, serverA := net.Pipe()
		clientB, serverB := net.Pipe()

		var wg sync.WaitGroup
		wg.Add(4)

		start := time.Now()

		// Send data A -> pipe
		go func() {
			defer wg.Done()
			clientA.Write(data)
			clientA.Close()
		}()

		// Read data from pipe -> B
		go func() {
			defer wg.Done()
			n, _ := io.Copy(io.Discard, clientB)
			totalBytes += n
		}()

		// Send data B -> pipe
		go func() {
			defer wg.Done()
			serverB.Write(data)
			serverB.Close()
		}()

		// Bidirectional pipe between serverA and clientB via a relay
		go func() {
			defer wg.Done()
			bidirPipe(serverA, serverB)
		}()

		wg.Wait()
		totalDuration += time.Since(start)
	}

	avgDuration := totalDuration / time.Duration(iterations)
	avgBytes := float64(size*2) // both directions
	throughput := avgBytes / avgDuration.Seconds() / (1024 * 1024)

	t.Logf("Bidirectional Pipe (net.Pipe): Avg Duration: %v, Throughput: %.2f MB/s",
		avgDuration, throughput)
}

func bytesToHuman(b int) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%d%cB", b/int(div), "KMGTPE"[exp])
}

// BenchmarkTunnelSimulation simulates a realistic tunnel scenario
// Client -> PublicServer -> (tunnel) -> Agent -> LocalService
func BenchmarkTunnelSimulation(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	rand.Read(data)

	// Simulate "local service"
	localService, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer localService.Close()

	// Local service echo handler
	go func() {
		for {
			conn, err := localService.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // Echo back
			}(conn)
		}
	}()

	// Simulate "public server" (tunnel entry)
	publicServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer publicServer.Close()

	// Tunnel relay handler
	go func() {
		for {
			clientConn, err := publicServer.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()
				// Connect to local service (simulating agent)
				local, err := net.Dial("tcp", localService.Addr().String())
				if err != nil {
					return
				}
				defer local.Close()
				// Bidirectional relay
				bidirPipe(client, local)
			}(clientConn)
		}
	}()

	b.SetBytes(int64(len(data) * 2)) // Request + Response
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("tcp", publicServer.Addr().String())
		if err != nil {
			b.Fatal(err)
		}

		// Send data
		go func() {
			conn.Write(data)
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
		}()

		// Read echo response
		io.Copy(io.Discard, conn)
		conn.Close()
	}
}

// BenchmarkTunnelSimulationWithPool measures improvement from connection pooling
func BenchmarkTunnelSimulationWithPool(b *testing.B) {
	data := make([]byte, 64*1024) // 64KB - more realistic for web requests
	rand.Read(data)

	// Simulate "local service"
	localService, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer localService.Close()

	go func() {
		for {
			conn, err := localService.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Connection pool
	poolSize := 10
	pool := make(chan net.Conn, poolSize)

	// Fill pool
	for i := 0; i < poolSize; i++ {
		conn, err := net.Dial("tcp", localService.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		pool <- conn
	}

	b.Run("WithoutPool", func(b *testing.B) {
		b.SetBytes(int64(len(data) * 2))
		for i := 0; i < b.N; i++ {
			conn, _ := net.Dial("tcp", localService.Addr().String())
			conn.Write(data)
			buf := make([]byte, len(data))
			io.ReadFull(conn, buf)
			conn.Close()
		}
	})

	b.Run("WithPool", func(b *testing.B) {
		b.SetBytes(int64(len(data) * 2))
		for i := 0; i < b.N; i++ {
			// Get from pool
			conn := <-pool
			conn.Write(data)
			buf := make([]byte, len(data))
			io.ReadFull(conn, buf)
			// Return to pool
			pool <- conn
		}
	})

	// Cleanup
	close(pool)
	for conn := range pool {
		conn.Close()
	}
}

// TestPerformanceSummary prints a summary of key metrics
func TestPerformanceSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	t.Log("=== Performance Summary ===")
	t.Log("")

	// Test 1: Connection establishment time
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	iterations := 100
	start := time.Now()
	for i := 0; i < iterations; i++ {
		c, _ := net.Dial("tcp", ln.Addr().String())
		c.Close()
	}
	connTime := time.Since(start) / time.Duration(iterations)
	ln.Close()

	t.Logf("TCP Connection Time: %v", connTime)

	// Test 2: Copy buffer pool efficiency
	poolStart := time.Now()
	for i := 0; i < 10000; i++ {
		buf := copyBufPool.Get().([]byte)
		_ = buf[0]
		copyBufPool.Put(buf)
	}
	poolTime := time.Since(poolStart)
	t.Logf("Buffer Pool (10000 get/put): %v (%.0f ns/op)", poolTime, float64(poolTime.Nanoseconds())/10000)

	// Test 3: Throughput
	data := make([]byte, 100*1024*1024) // 100MB
	rand.Read(data)

	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln2.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	throughputStart := time.Now()
	go func() {
		defer wg.Done()
		c, _ := ln2.Accept()
		defer c.Close()
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetReadBuffer(256 * 1024)
		}
		io.Copy(io.Discard, c)
	}()
	go func() {
		defer wg.Done()
		c, _ := net.Dial("tcp", ln2.Addr().String())
		defer c.Close()
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetWriteBuffer(256 * 1024)
		}
		c.Write(data)
	}()
	wg.Wait()
	throughputDuration := time.Since(throughputStart)
	throughput := float64(len(data)) / throughputDuration.Seconds() / (1024 * 1024 * 1024)

	t.Logf("TCP Throughput (100MB): %.2f GB/s", throughput)

	t.Log("")
	t.Log("=== Recommendations ===")
	if connTime > 100*time.Microsecond {
		t.Log("- Connection time is high. Ensure connection pooling is enabled.")
	}
	if throughput < 1.0 {
		t.Log("- Throughput is below 1 GB/s. Check network configuration.")
	}
	t.Log("- For production, enable TCP_NODELAY for latency-sensitive traffic")
	t.Log("- Use preconnect pools for high-connection-rate workloads")
	t.Log("- Consider TLS session resumption for encrypted tunnels")
}
