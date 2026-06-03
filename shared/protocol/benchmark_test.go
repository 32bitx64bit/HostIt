package protocol

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
)

// BenchmarkMarshalUDP measures the cost of serializing a UDP packet into a wire
// frame for a range of payload sizes representative of real tunnel traffic
// (small DNS replies, medium game packets, full MTU-sized datagrams).
func BenchmarkMarshalUDP(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192, 32 * 1024}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			pkt := &Packet{
				Type:    TypeData,
				Route:   "benchroute",
				Client:  "clientabc",
				Payload: make([]byte, n),
			}
			buf := make([]byte, 65536)
			b.ReportAllocs()
			b.SetBytes(int64(n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := MarshalUDP(pkt, buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUnmarshalUDP measures the inverse: parsing a UDP frame back into a
// Packet struct. This runs on every incoming public UDP datagram on the server
// and on every server-side datagram delivered to the agent, so the cost is
// paid twice per packet.
func BenchmarkUnmarshalUDP(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192, 32 * 1024}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			src := &Packet{
				Type:    TypeData,
				Route:   "benchroute",
				Client:  "clientabc",
				Payload: make([]byte, n),
			}
			frame, err := MarshalUDP(src, make([]byte, 65536))
			if err != nil {
				b.Fatal(err)
			}
			var dst Packet
			b.ReportAllocs()
			b.SetBytes(int64(n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := UnmarshalUDPTo(frame, &dst); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkWritePacket measures the cost of framing a TCP packet (used on the
// control channel and on per-route data sockets). The control channel runs
// HELLO/Ping/Pong/route-management packets at high frequency and writes happen
// under a session-level write mutex, so per-call cost directly throttles the
// control plane.
func BenchmarkWritePacket(b *testing.B) {
	sizes := []int{0, 64, 512, 4096, MaxPayloadSize}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			pkt := &Packet{
				Type:    TypeData,
				Route:   "benchroute",
				Client:  "clientabc",
				Payload: make([]byte, n),
			}
			var buf bytes.Buffer
			buf.Grow(5 + len(pkt.Route) + len(pkt.Client) + n)
			b.ReportAllocs()
			b.SetBytes(int64(n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				if err := WritePacket(&buf, pkt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkReadPacket measures the matching read path used by the control
// channel receive loop. ReadPacket allocates per-packet (route/client/payload)
// and is therefore a primary candidate for the per-allocation overhead seen on
// high-rate control traffic.
func BenchmarkReadPacket(b *testing.B) {
	sizes := []int{0, 64, 512, 4096, MaxPayloadSize}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			pkt := &Packet{
				Type:    TypeData,
				Route:   "benchroute",
				Client:  "clientabc",
				Payload: make([]byte, n),
			}
			var buf bytes.Buffer
			if err := WritePacket(&buf, pkt); err != nil {
				b.Fatal(err)
			}
			raw := buf.Bytes()
			b.ReportAllocs()
			b.SetBytes(int64(n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := bytes.NewReader(raw)
				if _, err := ReadPacket(r); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkReadPacketTo measures the same path through the zero-allocation
// ReadPacketTo API that the server and agent control loops now use. With a
// destination Packet allocated once outside the loop, the only remaining
// allocations are the route/client string conversions (unavoidable today
// without unsafe) and the payload buffer on first read. Steady-state reads
// of same-size packets should approach 0 allocs.
func BenchmarkReadPacketTo(b *testing.B) {
	sizes := []int{0, 64, 512, 4096, MaxPayloadSize}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			pkt := &Packet{
				Type:    TypeData,
				Route:   "benchroute",
				Client:  "clientabc",
				Payload: make([]byte, n),
			}
			var buf bytes.Buffer
			if err := WritePacket(&buf, pkt); err != nil {
				b.Fatal(err)
			}
			raw := buf.Bytes()
			var dst Packet
			b.ReportAllocs()
			b.SetBytes(int64(n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := ReadPacketTo(bytes.NewReader(raw), &dst); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUDPRoundTrip measures the full server-side path: read a datagram
// from a real loopback UDP socket, unmarshal it, mutate it (re-marshal with
// new client), and write it back out. This is the closest local reproduction
// of acceptPublicUDP + acceptAgentUDP's per-packet work and surfaces any
// encoding/decoding bottleneck that an in-memory benchmark would miss (e.g.
// syscall overhead, GC pressure on socket buffers).
func BenchmarkUDPRoundTrip(b *testing.B) {
	sizes := []int{64, 512, 1400, 8192}
	for _, n := range sizes {
		b.Run(payloadName(n), func(b *testing.B) {
			server, err := net.ListenUDP("udp", nil)
			if err != nil {
				b.Fatal(err)
			}
			defer server.Close()
			server.SetReadBuffer(8 * 1024 * 1024)
			server.SetWriteBuffer(8 * 1024 * 1024)

			client, err := net.ListenUDP("udp", nil)
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()

			clientAddr := client.LocalAddr().(*net.UDPAddr)
			serverAddr := server.LocalAddr().(*net.UDPAddr)

			payload := make([]byte, n)
			rand.Read(payload)
			outPkt := &Packet{
				Type:    TypeData,
				Route:   "rt",
				Client:  "c1",
				Payload: payload,
			}
			outFrame, err := MarshalUDP(outPkt, make([]byte, 65536))
			if err != nil {
				b.Fatal(err)
			}

			var inPkt Packet
			replyBuf := make([]byte, 65536)
			readBuf := make([]byte, 65536)
			b.ReportAllocs()
			b.SetBytes(int64(n))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := client.WriteToUDP(outFrame, serverAddr); err != nil {
					b.Fatal(err)
				}
				rn, _, err := server.ReadFromUDP(readBuf)
				if err != nil {
					b.Fatal(err)
				}
				if err := UnmarshalUDPTo(readBuf[:rn], &inPkt); err != nil {
					b.Fatal(err)
				}
				replyPkt := &Packet{
					Type:    TypeData,
					Route:   inPkt.Route,
					Client:  inPkt.Client,
					Payload: inPkt.Payload,
				}
				reply, err := MarshalUDP(replyPkt, replyBuf)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := server.WriteToUDP(reply, clientAddr); err != nil {
					b.Fatal(err)
				}
				if _, _, err := client.ReadFromUDP(readBuf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func payloadName(n int) string {
	switch {
	case n >= 1024:
		return formatKB(n)
	default:
		return formatB(n) + "B"
	}
}

func formatB(n int) string {
	if n == 0 {
		return "0"
	}
	return itoa(n)
}

func formatKB(n int) string {
	return itoa(n/1024) + "KB"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
