package protocol

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

type zeroProgressWriter struct{}

func (zeroProgressWriter) Write([]byte) (int, error) { return 0, nil }

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWritePacketRejectsOversizedFields(t *testing.T) {
	pkt := &Packet{
		Type:   TypeConnect,
		Route:  strings.Repeat("r", 256),
		Client: "ok",
	}
	if err := WritePacket(&bytes.Buffer{}, pkt); !errors.Is(err, ErrFieldTooLong) {
		t.Fatalf("WritePacket error = %v, want %v", err, ErrFieldTooLong)
	}
}

func TestMarshalUDPRejectsOversizedFields(t *testing.T) {
	pkt := &Packet{
		Type:   TypeData,
		Route:  "ok",
		Client: strings.Repeat("c", 256),
	}
	if _, err := MarshalUDP(pkt, nil); !errors.Is(err, ErrFieldTooLong) {
		t.Fatalf("MarshalUDP error = %v, want %v", err, ErrFieldTooLong)
	}
}

func TestMarshalUDPUnmarshalUDPRoundTrip(t *testing.T) {
	cases := []*Packet{
		{Type: TypeData, Route: "mail", Client: "abc123", Payload: []byte("hello world")},
		{Type: TypePing, Route: "", Client: "", Payload: nil},
		{Type: TypeRegister, Route: "hostit_mail_outbound", Client: "", Payload: []byte{}},
		{Type: TypePong, Route: "", Client: "client1", Payload: []byte("p")},
		{Type: TypeHello, Route: "r", Client: "", Payload: make([]byte, 1024)},
	}
	for _, orig := range cases {
		data, err := MarshalUDP(orig, nil)
		if err != nil {
			t.Fatalf("MarshalUDP error: %v", err)
		}
		got := &Packet{}
		if err := UnmarshalUDPTo(data, got); err != nil {
			t.Fatalf("UnmarshalUDPTo error: %v", err)
		}
		if got.Type != orig.Type {
			t.Fatalf("Type mismatch: got %d, want %d", got.Type, orig.Type)
		}
		if got.Route != orig.Route {
			t.Fatalf("Route mismatch: got %q, want %q", got.Route, orig.Route)
		}
		if got.Client != orig.Client {
			t.Fatalf("Client mismatch: got %q, want %q", got.Client, orig.Client)
		}
		if !bytes.Equal(got.Payload, orig.Payload) {
			t.Fatalf("Payload mismatch: got %v, want %v", got.Payload, orig.Payload)
		}
	}
}

func TestWritePacketReadPacketRoundTrip(t *testing.T) {
	pkt := &Packet{
		Type:    TypeConnect,
		Route:   "mail",
		Client:  "client-42",
		Payload: []byte("some data here"),
	}

	var buf bytes.Buffer
	if err := WritePacket(&buf, pkt); err != nil {
		t.Fatalf("WritePacket error: %v", err)
	}

	got, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket error: %v", err)
	}
	if got.Type != pkt.Type || got.Route != pkt.Route || got.Client != pkt.Client || !bytes.Equal(got.Payload, pkt.Payload) {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, pkt)
	}
}

func TestWritePacketHandlesWriterFailures(t *testing.T) {
	pkt := &Packet{Type: TypePing, Payload: []byte("ping")}

	if err := WritePacket(zeroProgressWriter{}, pkt); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WritePacket zero-progress error = %v, want %v", err, io.ErrShortWrite)
	}

	boom := errors.New("boom")
	if err := WritePacket(failingWriter{err: boom}, pkt); !errors.Is(err, boom) {
		t.Fatalf("WritePacket writer error = %v, want %v", err, boom)
	}
}

func TestMaxSizedFieldsAndPayloadRoundTrip(t *testing.T) {
	payload := make([]byte, MaxPayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := &Packet{
		Type:    TypeData,
		Route:   strings.Repeat("r", 255),
		Client:  strings.Repeat("c", 255),
		Payload: payload,
	}

	var buf bytes.Buffer
	if err := WritePacket(&buf, pkt); err != nil {
		t.Fatalf("WritePacket max packet: %v", err)
	}
	got, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket max packet: %v", err)
	}
	if got.Type != pkt.Type || got.Route != pkt.Route || got.Client != pkt.Client || !bytes.Equal(got.Payload, pkt.Payload) {
		t.Fatal("max-sized TCP packet did not round-trip")
	}

	udpData, err := MarshalUDP(pkt, nil)
	if err != nil {
		t.Fatalf("MarshalUDP max packet: %v", err)
	}
	var udpGot Packet
	if err := UnmarshalUDPTo(udpData, &udpGot); err != nil {
		t.Fatalf("UnmarshalUDPTo max packet: %v", err)
	}
	if udpGot.Type != pkt.Type || udpGot.Route != pkt.Route || udpGot.Client != pkt.Client || !bytes.Equal(udpGot.Payload, pkt.Payload) {
		t.Fatal("max-sized UDP packet did not round-trip")
	}
}

func TestWritePacketReadPacketViaPipe(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	pkt := &Packet{
		Type:    TypeData,
		Route:   "route1",
		Client:  "client1",
		Payload: []byte("payload-via-pipe"),
	}

	var wg sync.WaitGroup
	var writeErr, readErr error
	var readPkt *Packet

	wg.Add(2)
	go func() {
		defer wg.Done()
		writeErr = WritePacket(c1, pkt)
		io.Copy(io.Discard, c1)
	}()
	go func() {
		defer wg.Done()
		readPkt, readErr = ReadPacket(c2)
		c2.Close()
	}()
	wg.Wait()

	if writeErr != nil {
		t.Fatalf("WritePacket error: %v", writeErr)
	}
	if readErr != nil {
		t.Fatalf("ReadPacket error: %v", readErr)
	}
	if readPkt.Type != pkt.Type || readPkt.Route != pkt.Route || readPkt.Client != pkt.Client || !bytes.Equal(readPkt.Payload, pkt.Payload) {
		t.Fatalf("pipe round-trip mismatch: got %+v, want %+v", readPkt, pkt)
	}
}

func TestMaxPayloadSizeEnforcement(t *testing.T) {
	pkt := &Packet{
		Type:    TypeData,
		Payload: make([]byte, MaxPayloadSize+1),
	}
	if err := WritePacket(&bytes.Buffer{}, pkt); !errors.Is(err, ErrPayloadTooBig) {
		t.Fatalf("WritePacket error = %v, want ErrPayloadTooBig", err)
	}
	if _, err := MarshalUDP(pkt, nil); !errors.Is(err, ErrPayloadTooBig) {
		t.Fatalf("MarshalUDP error = %v, want ErrPayloadTooBig", err)
	}
}

func TestUDPFrameSizeHelpers(t *testing.T) {
	if got, want := UDPFrameLen("game", "127.0.0.1:40000", 1200), 1+1+len("game")+1+len("127.0.0.1:40000")+1200; got != want {
		t.Fatalf("UDPFrameLen() = %d, want %d", got, want)
	}
	if UDPFrameLen("", "", -1) != 3 {
		t.Fatal("UDPFrameLen should clamp negative payload lengths to zero")
	}
	if UDPFrameExceedsRecommendedSize(RecommendedMaxUDPDatagramSize) {
		t.Fatal("recommended max size should not exceed itself")
	}
	if !UDPFrameExceedsRecommendedSize(RecommendedMaxUDPDatagramSize + 1) {
		t.Fatal("frame above recommended max size should be reported")
	}
}

func TestEmptyFieldsRoundTrip(t *testing.T) {
	pkt := &Packet{Type: TypePing, Route: "", Client: "", Payload: nil}

	data, err := MarshalUDP(pkt, nil)
	if err != nil {
		t.Fatalf("MarshalUDP: %v", err)
	}
	got := &Packet{}
	if err := UnmarshalUDPTo(data, got); err != nil {
		t.Fatalf("UnmarshalUDPTo: %v", err)
	}
	if got.Type != TypePing || got.Route != "" || got.Client != "" || len(got.Payload) != 0 {
		t.Fatalf("unexpected: %+v", got)
	}

	var buf bytes.Buffer
	if err := WritePacket(&buf, pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	got2, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if got2.Type != TypePing || got2.Route != "" || got2.Client != "" || len(got2.Payload) != 0 {
		t.Fatalf("unexpected: %+v", got2)
	}
}

func TestUnmarshalUDPToUnknownType(t *testing.T) {
	data := []byte{0, 0, 0}
	p := &Packet{}
	if err := UnmarshalUDPTo(data, p); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("UnmarshalUDPTo with type 0: error = %v, want ErrInvalidPacket", err)
	}

	data2 := []byte{99, 0, 0}
	if err := UnmarshalUDPTo(data2, p); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("UnmarshalUDPTo with type 99: error = %v, want ErrInvalidPacket", err)
	}
}

func TestUnmarshalUDPToRejectsTruncatedPackets(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "one byte", data: []byte{TypeData}},
		{name: "missing client length", data: []byte{TypeData, 1, 'r'}},
		{name: "route length beyond packet", data: []byte{TypeData, 5, 'r', '1'}},
		{name: "client length beyond packet", data: []byte{TypeData, 1, 'r', 5, 'c'}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pkt Packet
			if err := UnmarshalUDPTo(tt.data, &pkt); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("UnmarshalUDPTo error = %v, want ErrInvalidPacket", err)
			}
		})
	}
}

func TestNewPacketTypesRoundTrip(t *testing.T) {
	newTypes := []struct {
		Type    byte
		Name    string
		Payload []byte
	}{
		{TypeRouteRequest, "route-req", []byte(`{"name":"app"}`)},
		{TypeRouteResponse, "route-resp", []byte(`{"status":"active"}`)},
		{TypeRouteConfirm, "route-confirm", []byte(`{"name":"app","domain":"app.example.com"}`)},
		{TypeRouteAck, "route-ack", []byte(`{"status":"active"}`)},
		{TypeRouteRemove, "route-remove", []byte(`{"name":"app"}`)},
		{TypeRouteRemoveAck, "route-remove-ack", []byte(`{"ok":true}`)},
	}

	for _, tc := range newTypes {
		t.Run(tc.Name, func(t *testing.T) {
			pkt := &Packet{
				Type:    tc.Type,
				Route:   tc.Name,
				Client:  "client-1",
				Payload: tc.Payload,
			}

			var buf bytes.Buffer
			if err := WritePacket(&buf, pkt); err != nil {
				t.Fatalf("WritePacket: %v", err)
			}
			got, err := ReadPacket(&buf)
			if err != nil {
				t.Fatalf("ReadPacket: %v", err)
			}
			if got.Type != pkt.Type || got.Route != pkt.Route || got.Client != pkt.Client || !bytes.Equal(got.Payload, pkt.Payload) {
				t.Fatalf("TCP round-trip mismatch: got %+v, want %+v", got, pkt)
			}

			udpData, err := MarshalUDP(pkt, nil)
			if err != nil {
				t.Fatalf("MarshalUDP: %v", err)
			}
			var udpGot Packet
			if err := UnmarshalUDPTo(udpData, &udpGot); err != nil {
				t.Fatalf("UnmarshalUDPTo: %v", err)
			}
			if udpGot.Type != pkt.Type || udpGot.Route != pkt.Route || udpGot.Client != pkt.Client || !bytes.Equal(udpGot.Payload, pkt.Payload) {
				t.Fatalf("UDP round-trip mismatch: got %+v, want %+v", udpGot, pkt)
			}
		})
	}
}

func TestUnmarshalUDPToRejectsOutOfRangePacketType(t *testing.T) {
	cases := []struct {
		name    string
		typeVal byte
	}{
		{"zero", 0},
		{"too_high", 17},
		{"way_too_high", 255},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte{tc.typeVal, 0, 0}
			var pkt Packet
			if err := UnmarshalUDPTo(data, &pkt); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("UnmarshalUDPTo with type %d: error = %v, want ErrInvalidPacket", tc.typeVal, err)
			}
		})
	}
}

// TestUnmarshalUDPToStringsOutliveInputBuffer guards the contract that
// p.Route and p.Client returned by UnmarshalUDPTo are independent of the
// input buffer, even though they are stored in the Packet's own scratch
// (not aliased to the caller's reused read buffer). The production UDP
// hot path reuses its read buffer for every datagram, so the next
// ReadFromUDPAddrPort must not invalidate strings from the previous
// parse. This was the bug that broke UDP forwarding (Sunshine remote
// desktop showed a black screen because the route cache lookups were
// returning the wrong route and silently dropping packets).
func TestUnmarshalUDPToStringsOutliveInputBuffer(t *testing.T) {
	// Wire format: [type:1][routeLen:1][route][clientLen:1][client][payload]
	first := []byte{TypeData, 5, 'r', 'o', 'u', 't', 'e', 1, 'A'}
	second := []byte{TypeData, 5, 'r', 'o', 'u', 't', 'e', 1, 'B'}

	buf := make([]byte, 64)
	copy(buf, first)

	var pkt Packet
	if err := UnmarshalUDPTo(buf[:len(first)], &pkt); err != nil {
		t.Fatal(err)
	}
	if pkt.Route != "route" || pkt.Client != "A" {
		t.Fatalf("first read: route=%q client=%q, want route/A", pkt.Route, pkt.Client)
	}

	// Capture the strings. After the buffer is overwritten and the
	// next datagram is parsed, these captured strings must still hold
	// the first packet's route and client — they are copies into the
	// Packet's own scratch, not aliases of buf.
	routeA := pkt.Route
	clientA := pkt.Client

	for i := range buf {
		buf[i] = 0
	}
	copy(buf, second)

	if err := UnmarshalUDPTo(buf[:len(second)], &pkt); err != nil {
		t.Fatal(err)
	}
	if routeA != "route" || clientA != "A" {
		t.Fatalf("captured strings mutated after buffer reuse: routeA=%q clientA=%q, want route/A "+
			"(UnmarshalUDPTo aliased the caller's buffer)", routeA, clientA)
	}
}

func TestUnmarshalUDPToReusesReadBufferStress(t *testing.T) {
	routes := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	buf := make([]byte, 64)
	var pkt Packet
	for i := 0; i < 1000; i++ {
		route := routes[i%len(routes)]
		expected := []byte{TypeData, byte(len(route))}
		expected = append(expected, []byte(route)...)
		expected = append(expected, 1, 'A')

		for j := range buf {
			buf[j] = 0
		}
		copy(buf, expected)

		if err := UnmarshalUDPTo(buf[:len(expected)], &pkt); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if pkt.Route != route {
			t.Fatalf("iter %d: route = %q, want %q (buffer aliasing?)", i, pkt.Route, route)
		}
		if pkt.Client != "A" {
			t.Fatalf("iter %d: client = %q, want A (buffer aliasing?)", i, pkt.Client)
		}
	}
}

func TestReadPacketReturnsErrorForTruncatedFrames(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "partial header", data: []byte{TypeData, 0}},
		{name: "truncated route", data: []byte{TypeData, 3, 0, 0, 0, 'r'}},
		{name: "truncated client", data: []byte{TypeData, 0, 3, 0, 0, 'c'}},
		{name: "truncated payload", data: []byte{TypeData, 0, 0, 0, 3, 'p'}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ReadPacket(bytes.NewReader(tt.data)); err == nil {
				t.Fatal("ReadPacket error = nil, want error")
			}
		})
	}
}

// TestReadPacketToOverwritesInPlace guards the zero-allocation control-loop
// API. ReadPacketTo must always overwrite every field of the destination
// packet and must not retain references to the previous payload's backing
// array in a way that would leak memory when the same packet is reused
// across many iterations.
func TestReadPacketToOverwritesInPlace(t *testing.T) {
	// Build two distinct packets and verify that the second ReadPacketTo
	// call produces the second packet's contents even though we reuse the
	// destination struct (i.e. previous Route/Client/Payload do not leak
	// through).
	first := &Packet{Type: TypeData, Route: "firstroute", Client: "firstclient", Payload: []byte("first payload")}
	second := &Packet{Type: TypePing, Route: "second", Client: "sc", Payload: []byte("p")}

	var buf bytes.Buffer
	if err := WritePacket(&buf, first); err != nil {
		t.Fatal(err)
	}
	if err := WritePacket(&buf, second); err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(buf.Bytes())
	var pkt Packet
	if err := ReadPacketTo(r, &pkt); err != nil {
		t.Fatalf("ReadPacketTo 1: %v", err)
	}
	if pkt.Type != first.Type || pkt.Route != first.Route || pkt.Client != first.Client || !bytes.Equal(pkt.Payload, first.Payload) {
		t.Fatalf("first read = %+v, want %+v", pkt, *first)
	}
	if err := ReadPacketTo(r, &pkt); err != nil {
		t.Fatalf("ReadPacketTo 2: %v", err)
	}
	if pkt.Type != second.Type || pkt.Route != second.Route || pkt.Client != second.Client || !bytes.Equal(pkt.Payload, second.Payload) {
		t.Fatalf("second read = %+v, want %+v", pkt, *second)
	}

	// The ReadPacketTo path must also handle the maximum-sized payload
	// (uint16 max, since the field is uint16 and 65535 is the largest
	// value that fits). Larger values cannot be expressed on the wire
	// format, so we don't need an oversize test here.
	maxPayload := &Packet{Type: TypeData, Payload: bytes.Repeat([]byte{0xAB}, MaxPayloadSize)}
	var maxBuf bytes.Buffer
	if err := WritePacket(&maxBuf, maxPayload); err != nil {
		t.Fatal(err)
	}
	if err := ReadPacketTo(bytes.NewReader(maxBuf.Bytes()), &pkt); err != nil {
		t.Fatalf("max-size read: %v", err)
	}
	if len(pkt.Payload) != MaxPayloadSize {
		t.Fatalf("max-size payload len = %d, want %d", len(pkt.Payload), MaxPayloadSize)
	}
}

// TestReadPacketToReusesPayloadBuffer verifies that repeated reads of the
// same payload length reuse the existing backing array instead of allocating
// a new one each iteration. This is the per-iteration allocation we care
// about: a control loop reading a stream of same-size packets must not
// churn the heap.
func TestReadPacketToReusesPayloadBuffer(t *testing.T) {
	body := &Packet{Type: TypePing, Payload: []byte("pingpayload")}
	var buf bytes.Buffer
	for i := 0; i < 5; i++ {
		if err := WritePacket(&buf, body); err != nil {
			t.Fatal(err)
		}
	}
	r := bytes.NewReader(buf.Bytes())
	var pkt Packet
	firstCap := 0
	for i := 0; i < 5; i++ {
		if err := ReadPacketTo(r, &pkt); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstCap = cap(pkt.Payload)
		} else if cap(pkt.Payload) != firstCap {
			t.Fatalf("iteration %d: payload cap = %d, want %d (backing array not reused)", i, cap(pkt.Payload), firstCap)
		}
	}
}

// TestReadPacketToEmptyRouteAndClient exercises the common control-plane
// case where Route and Client are absent. The packet's Route/Client fields
// must be reset to empty strings, not retain stale values from a previous
// read.
func TestReadPacketToEmptyRouteAndClient(t *testing.T) {
	withFields := &Packet{Type: TypeData, Route: "x", Client: "y", Payload: []byte("p")}
	empty := &Packet{Type: TypePing, Payload: []byte("p")}

	var b2 bytes.Buffer
	if err := WritePacket(&b2, withFields); err != nil {
		t.Fatal(err)
	}
	if err := WritePacket(&b2, empty); err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(b2.Bytes())
	var pkt Packet
	if err := ReadPacketTo(r, &pkt); err != nil {
		t.Fatal(err)
	}
	if pkt.Route != "x" || pkt.Client != "y" {
		t.Fatalf("first read: route=%q client=%q, want x/y", pkt.Route, pkt.Client)
	}
	if err := ReadPacketTo(r, &pkt); err != nil {
		t.Fatal(err)
	}
	if pkt.Route != "" || pkt.Client != "" {
		t.Fatalf("second read: route=%q client=%q, want empty/empty", pkt.Route, pkt.Client)
	}
	if !bytes.Equal(pkt.Payload, empty.Payload) {
		t.Fatalf("payload = %q, want %q", pkt.Payload, empty.Payload)
	}
}
