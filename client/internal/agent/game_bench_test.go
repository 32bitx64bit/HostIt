package agent

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Minecraft-like traffic patterns:
// - Player position updates: ~20 packets/sec, 20-50 bytes each
// - Block updates: variable, 10-100 bytes
// - Chunk data: 16KB-256KB per chunk, sent on world load/exploration
// - Keep-alive: every 15-20 seconds, small packets
// - Chat: variable, 50-500 bytes

// BenchmarkMinecraftPlayerMovement simulates player position packets (20 ticks/sec)
func BenchmarkMinecraftPlayerMovement(b *testing.B) {
	// Typical player position packet: ~26 bytes
	// X, Y, Z (doubles = 24 bytes) + flags (2 bytes)
	packet := make([]byte, 26)
	rand.Read(packet)

	server, client := createTunnelPair(b)
	defer server.Close()
	defer client.Close()

	b.SetBytes(int64(len(packet)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		client.Write(packet)
		buf := make([]byte, len(packet))
		io.ReadFull(server, buf)
	}
}

// BenchmarkMinecraftChunkLoad simulates chunk data transfer
func BenchmarkMinecraftChunkLoad(b *testing.B) {
	// Minecraft chunk: typically 16x256x16 blocks
	// Compressed chunk data is usually 16KB-64KB
	chunkSizes := []int{
		16 * 1024,  // 16KB - small/sparse chunk
		32 * 1024,  // 32KB - average chunk
		64 * 1024,  // 64KB - dense chunk
		128 * 1024, // 128KB - chunk with lots of entities/tile data
	}

	for _, size := range chunkSizes {
		b.Run(fmt.Sprintf("Chunk_%dKB", size/1024), func(b *testing.B) {
			chunk := make([]byte, size)
			rand.Read(chunk)

			server, client := createTunnelPair(b)
			defer server.Close()
			defer client.Close()

			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				client.Write(chunk)
				buf := make([]byte, size)
				io.ReadFull(server, buf)
			}
		})
	}
}

// BenchmarkMinecraftMixedTraffic simulates realistic mixed game traffic
func BenchmarkMinecraftMixedTraffic(b *testing.B) {
	server, client := createTunnelPair(b)
	defer server.Close()
	defer client.Close()

	// Prepare different packet types
	positionPacket := make([]byte, 26)   // Player position
	blockUpdate := make([]byte, 12)      // Block change
	chatPacket := make([]byte, 256)      // Chat message
	keepAlive := make([]byte, 8)         // Keep-alive
	
	rand.Read(positionPacket)
	rand.Read(blockUpdate)
	rand.Read(chatPacket)
	rand.Read(keepAlive)

	// Traffic distribution (per 100 packets):
	// 70% position updates, 20% block updates, 8% other, 2% chat
	packets := make([][]byte, 100)
	for i := 0; i < 70; i++ {
		packets[i] = positionPacket
	}
	for i := 70; i < 90; i++ {
		packets[i] = blockUpdate
	}
	for i := 90; i < 98; i++ {
		packets[i] = keepAlive
	}
	for i := 98; i < 100; i++ {
		packets[i] = chatPacket
	}

	var totalBytes int64
	for _, p := range packets {
		totalBytes += int64(len(p))
	}

	b.SetBytes(totalBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, packet := range packets {
			client.Write(packet)
			buf := make([]byte, len(packet))
			io.ReadFull(server, buf)
		}
	}
}

// BenchmarkMinecraftLatency measures round-trip latency for game packets
func BenchmarkMinecraftLatency(b *testing.B) {
	// Echo server (simulates game server responding to player actions)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
				}
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Tunnel relay
	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer tunnelLn.Close()

	go func() {
		for {
			client, err := tunnelLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
				}
				backend, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					return
				}
				defer backend.Close()
				if tc, ok := backend.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
				}
				bidirPipe(c, backend)
			}(client)
		}
	}()

	// Player position packet
	packet := make([]byte, 26)
	rand.Read(packet)

	conn, err := net.Dial("tcp", tunnelLn.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	buf := make([]byte, len(packet))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		conn.Write(packet)
		io.ReadFull(conn, buf)
	}
}

// TestMinecraftLatencyReport provides detailed latency analysis
func TestMinecraftLatencyReport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	t.Log("=== Minecraft Latency Simulation ===")
	t.Log("")

	// Game server (echo)
	gameServer, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gameServer.Close()

	go func() {
		for {
			conn, err := gameServer.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
					tc.SetReadBuffer(64 * 1024)
					tc.SetWriteBuffer(64 * 1024)
				}
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Tunnel relay
	tunnelEntry, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnelEntry.Close()

	go func() {
		for {
			client, err := tunnelEntry.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
					tc.SetReadBuffer(64 * 1024)
					tc.SetWriteBuffer(64 * 1024)
				}
				backend, _ := net.Dial("tcp", gameServer.Addr().String())
				if backend == nil {
					return
				}
				defer backend.Close()
				if tc, ok := backend.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
					tc.SetReadBuffer(64 * 1024)
					tc.SetWriteBuffer(64 * 1024)
				}
				bidirPipe(c, backend)
			}(client)
		}
	}()

	// Test packets
	posPacket := make([]byte, 26)   // Player position
	chunkPacket := make([]byte, 32*1024) // Chunk data
	rand.Read(posPacket)
	rand.Read(chunkPacket)

	// Measure direct latency (no tunnel)
	directLatencies := measureLatencies(t, gameServer.Addr().String(), posPacket, 1000)
	t.Logf("Direct Connection (no tunnel):")
	printLatencyStats(t, directLatencies)

	// Measure tunneled latency
	tunneledLatencies := measureLatencies(t, tunnelEntry.Addr().String(), posPacket, 1000)
	t.Logf("Through Tunnel:")
	printLatencyStats(t, tunneledLatencies)

	// Calculate overhead
	directAvg := avgDuration(directLatencies)
	tunneledAvg := avgDuration(tunneledLatencies)
	overhead := tunneledAvg - directAvg
	overheadPct := float64(overhead) / float64(directAvg) * 100

	t.Log("")
	t.Logf("Tunnel Overhead: %v (%.1f%%)", overhead, overheadPct)
	t.Log("")

	// Chunk transfer test
	t.Log("=== Chunk Transfer Test ===")
	chunkStart := time.Now()
	conn, _ := net.Dial("tcp", tunnelEntry.Addr().String())
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	conn.Write(chunkPacket)
	buf := make([]byte, len(chunkPacket))
	io.ReadFull(conn, buf)
	chunkLatency := time.Since(chunkStart)
	conn.Close()

	throughput := float64(len(chunkPacket)*2) / chunkLatency.Seconds() / (1024 * 1024)
	t.Logf("32KB Chunk Round-Trip: %v (%.2f MB/s)", chunkLatency, throughput)

	// Recommendations
	t.Log("")
	t.Log("=== Gaming Recommendations ===")
	if tunneledAvg > 5*time.Millisecond {
		t.Log("⚠️  High latency detected. For competitive gaming:")
		t.Log("   - Ensure server and client are geographically close")
		t.Log("   - Use wired connection instead of WiFi")
		t.Log("   - Disable TLS if security isn't critical (tunnelTLS=false)")
	}
	if overhead > 1*time.Millisecond {
		t.Log("⚠️  Tunnel overhead is significant:")
		t.Log("   - Increase preconnect pool size")
		t.Log("   - Ensure TCP_NODELAY is enabled (default)")
	}
	if tunneledAvg < 1*time.Millisecond {
		t.Log("✓ Excellent latency for gaming!")
	}
}

// TestMinecraftThroughputReport tests sustained throughput for world downloads
func TestMinecraftThroughputReport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	t.Log("=== Minecraft World Download Simulation ===")
	t.Log("")

	// Simulate downloading chunks when joining a server
	// Typically loads ~300-500 chunks (render distance 12-16)
	numChunks := 400
	chunkSize := 32 * 1024 // 32KB average
	totalData := numChunks * chunkSize

	t.Logf("Simulating: %d chunks × %dKB = %.1f MB total",
		numChunks, chunkSize/1024, float64(totalData)/(1024*1024))
	t.Log("")

	// Server that sends chunk data
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	chunkData := make([]byte, chunkSize)
	rand.Read(chunkData)

	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetWriteBuffer(256 * 1024)
				}
				// Send all chunks
				for i := 0; i < numChunks; i++ {
					c.Write(chunkData)
				}
			}(conn)
		}
	}()

	// Tunnel
	tunnel, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	go func() {
		for {
			client, err := tunnel.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetReadBuffer(256 * 1024)
					tc.SetWriteBuffer(256 * 1024)
				}
				backend, _ := net.Dial("tcp", server.Addr().String())
				if backend == nil {
					return
				}
				defer backend.Close()
				if tc, ok := backend.(*net.TCPConn); ok {
					tc.SetReadBuffer(256 * 1024)
					tc.SetWriteBuffer(256 * 1024)
				}
				bidirPipe(c, backend)
			}(client)
		}
	}()

	// Direct download
	t.Log("Direct Connection:")
	directStart := time.Now()
	directConn, _ := net.Dial("tcp", server.Addr().String())
	if tc, ok := directConn.(*net.TCPConn); ok {
		tc.SetReadBuffer(256 * 1024)
	}
	received := 0
	buf := make([]byte, 64*1024)
	for received < totalData {
		n, err := directConn.Read(buf)
		if err != nil {
			break
		}
		received += n
	}
	directConn.Close()
	directDuration := time.Since(directStart)
	directSpeed := float64(totalData) / directDuration.Seconds() / (1024 * 1024)
	t.Logf("  Time: %v, Speed: %.2f MB/s", directDuration, directSpeed)

	// Tunneled download
	t.Log("Through Tunnel:")
	tunnelStart := time.Now()
	tunnelConn, _ := net.Dial("tcp", tunnel.Addr().String())
	if tc, ok := tunnelConn.(*net.TCPConn); ok {
		tc.SetReadBuffer(256 * 1024)
	}
	received = 0
	for received < totalData {
		n, err := tunnelConn.Read(buf)
		if err != nil {
			break
		}
		received += n
	}
	tunnelConn.Close()
	tunnelDuration := time.Since(tunnelStart)
	tunnelSpeed := float64(totalData) / tunnelDuration.Seconds() / (1024 * 1024)
	t.Logf("  Time: %v, Speed: %.2f MB/s", tunnelDuration, tunnelSpeed)

	overhead := tunnelDuration - directDuration
	t.Log("")
	t.Logf("Tunnel Overhead: %v (%.1f%% slower)",
		overhead, float64(overhead)/float64(directDuration)*100)

	// Estimate real-world join time
	t.Log("")
	t.Log("=== Estimated Server Join Time ===")
	t.Logf("At %.0f MB/s: %.1f seconds to load world",
		tunnelSpeed, float64(totalData)/(tunnelSpeed*1024*1024))
}

// BenchmarkGamePacketSizes benchmarks common game packet sizes
func BenchmarkGamePacketSizes(b *testing.B) {
	sizes := map[string]int{
		"KeepAlive_8B":     8,
		"Position_26B":    26,
		"BlockChange_12B": 12,
		"Chat_256B":       256,
		"Entity_64B":      64,
		"Inventory_2KB":   2048,
		"Chunk_32KB":      32 * 1024,
		"MapData_128KB":   128 * 1024,
	}

	for name, size := range sizes {
		b.Run(name, func(b *testing.B) {
			packet := make([]byte, size)
			rand.Read(packet)

			server, client := createTunnelPair(b)
			defer server.Close()
			defer client.Close()

			b.SetBytes(int64(size * 2)) // Round trip
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				client.Write(packet)
				buf := make([]byte, size)
				io.ReadFull(server, buf)
			}
		})
	}
}

// BenchmarkConcurrentPlayers simulates multiple players on a server
func BenchmarkConcurrentPlayers(b *testing.B) {
	playerCounts := []int{1, 5, 10, 20, 50}

	for _, players := range playerCounts {
		b.Run(fmt.Sprintf("%d_players", players), func(b *testing.B) {
			// Game server
			gameServer, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer gameServer.Close()

			go func() {
				for {
					conn, err := gameServer.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						if tc, ok := c.(*net.TCPConn); ok {
							tc.SetNoDelay(true)
						}
						io.Copy(c, c)
					}(conn)
				}
			}()

			// Tunnel
			tunnel, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer tunnel.Close()

			go func() {
				for {
					client, err := tunnel.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						if tc, ok := c.(*net.TCPConn); ok {
							tc.SetNoDelay(true)
						}
						backend, _ := net.Dial("tcp", gameServer.Addr().String())
						if backend == nil {
							return
						}
						defer backend.Close()
						if tc, ok := backend.(*net.TCPConn); ok {
							tc.SetNoDelay(true)
						}
						bidirPipe(c, backend)
					}(client)
				}
			}()

			packet := make([]byte, 26) // Position update
			rand.Read(packet)

			// Create player connections
			conns := make([]net.Conn, players)
			for i := 0; i < players; i++ {
				conn, err := net.Dial("tcp", tunnel.Addr().String())
				if err != nil {
					b.Fatal(err)
				}
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
				}
				conns[i] = conn
			}
			defer func() {
				for _, c := range conns {
					c.Close()
				}
			}()

			b.SetBytes(int64(len(packet) * 2 * players))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				wg.Add(players)
				for _, conn := range conns {
					go func(c net.Conn) {
						defer wg.Done()
						c.Write(packet)
						buf := make([]byte, len(packet))
						io.ReadFull(c, buf)
					}(conn)
				}
				wg.Wait()
			}
		})
	}
}

// BenchmarkTickRate simulates different game tick rates
func BenchmarkTickRate(b *testing.B) {
	tickRates := map[string]int{
		"Minecraft_20tps":   20,
		"Terraria_60tps":    60,
		"Valheim_50tps":     50,
		"FastPaced_128tps":  128,
	}

	packet := make([]byte, 32) // Typical game state update
	rand.Read(packet)

	for name, tps := range tickRates {
		b.Run(name, func(b *testing.B) {
			server, client := createTunnelPair(b)
			defer server.Close()
			defer client.Close()

			tickInterval := time.Second / time.Duration(tps)
			
			b.ResetTimer()
			
			start := time.Now()
			ticks := 0
			for time.Since(start) < time.Second && ticks < b.N {
				client.Write(packet)
				buf := make([]byte, len(packet))
				io.ReadFull(server, buf)
				ticks++
				
				// Simulate tick timing (but don't actually sleep in benchmark)
				_ = tickInterval
			}
			
			b.ReportMetric(float64(ticks), "ticks/s")
		})
	}
}

// Helper functions

func createTunnelPair(b *testing.B) (server, client net.Conn) {
	// Echo server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
					tc.SetReadBuffer(64 * 1024)
					tc.SetWriteBuffer(64 * 1024)
				}
				io.Copy(c, c)
				c.Close()
			}(conn)
		}
	}()

	// Tunnel entry
	tunnelLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	var serverConn atomic.Pointer[net.Conn]

	go func() {
		for {
			client, err := tunnelLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
					tc.SetReadBuffer(64 * 1024)
					tc.SetWriteBuffer(64 * 1024)
				}
				backend, _ := net.Dial("tcp", ln.Addr().String())
				if backend == nil {
					c.Close()
					return
				}
				if tc, ok := backend.(*net.TCPConn); ok {
					tc.SetNoDelay(true)
					tc.SetReadBuffer(64 * 1024)
					tc.SetWriteBuffer(64 * 1024)
				}
				serverConn.Store(&backend)
				bidirPipe(c, backend)
			}(client)
		}
	}()

	// Connect client
	clientConn, err := net.Dial("tcp", tunnelLn.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(64 * 1024)
		tc.SetWriteBuffer(64 * 1024)
	}

	// Wait for tunnel to establish
	time.Sleep(10 * time.Millisecond)

	b.Cleanup(func() {
		ln.Close()
		tunnelLn.Close()
	})

	return clientConn, clientConn // Both ends use same connection for echo
}

func measureLatencies(t *testing.T, addr string, packet []byte, count int) []time.Duration {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	latencies := make([]time.Duration, count)
	buf := make([]byte, len(packet))

	// Warmup
	for i := 0; i < 100; i++ {
		conn.Write(packet)
		io.ReadFull(conn, buf)
	}

	for i := 0; i < count; i++ {
		start := time.Now()
		conn.Write(packet)
		io.ReadFull(conn, buf)
		latencies[i] = time.Since(start)
	}

	return latencies
}

func printLatencyStats(t *testing.T, latencies []time.Duration) {
	if len(latencies) == 0 {
		return
	}

	var total time.Duration
	min := latencies[0]
	max := latencies[0]

	for _, l := range latencies {
		total += l
		if l < min {
			min = l
		}
		if l > max {
			max = l
		}
	}

	avg := total / time.Duration(len(latencies))

	// Calculate P50, P95, P99
	sorted := make([]time.Duration, len(latencies))
	copy(sorted, latencies)
	sortDurations(sorted)

	p50 := sorted[len(sorted)*50/100]
	p95 := sorted[len(sorted)*95/100]
	p99 := sorted[len(sorted)*99/100]

	t.Logf("  Min: %v, Avg: %v, Max: %v", min, avg, max)
	t.Logf("  P50: %v, P95: %v, P99: %v", p50, p95, p99)
}

func sortDurations(d []time.Duration) {
	for i := 0; i < len(d); i++ {
		for j := i + 1; j < len(d); j++ {
			if d[j] < d[i] {
				d[i], d[j] = d[j], d[i]
			}
		}
	}
}

func avgDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	var total time.Duration
	for _, v := range d {
		total += v
	}
	return total / time.Duration(len(d))
}

// Length-prefixed packet helpers for more realistic game protocol simulation
func writePacket(conn net.Conn, data []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func readPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header)
	data := make([]byte, length)
	_, err := io.ReadFull(conn, data)
	return data, err
}
