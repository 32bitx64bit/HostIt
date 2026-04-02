package protocol

import (
	"bytes"
	"errors"
	"strings"
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
