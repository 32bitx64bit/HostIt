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
