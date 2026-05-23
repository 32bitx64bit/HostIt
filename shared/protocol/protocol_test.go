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
