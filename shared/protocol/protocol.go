package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

// Packet types
const (
	TypeRegister byte = 1
	TypeData     byte = 2
	TypePing     byte = 3
	TypePong     byte = 4
	TypeHello    byte = 5
	TypeConnect  byte = 6
)

// Protocol errors
var (
	ErrInvalidPacket = errors.New("invalid packet")
	ErrPayloadTooBig = errors.New("payload too big")
)

// MaxPayloadSize is the maximum size of a packet payload
const MaxPayloadSize = 64 * 1024 // 64KB

// Packet represents a single protocol message
type Packet struct {
	Type    byte
	Route   string
	Client  string
	Payload []byte
}

// WritePacket writes a packet to an io.Writer (for TCP)
func WritePacket(w io.Writer, p *Packet) error {
	routeBytes := []byte(p.Route)
	clientBytes := []byte(p.Client)

	if len(p.Payload) > MaxPayloadSize {
		return ErrPayloadTooBig
	}

	totalLen := 5 + len(routeBytes) + len(clientBytes) + len(p.Payload)
	buf := make([]byte, totalLen)

	// Header: [Type(1)] [RouteLen(1)] [ClientLen(1)] [PayloadLen(2)]
	buf[0] = p.Type
	buf[1] = byte(len(routeBytes))
	buf[2] = byte(len(clientBytes))
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(p.Payload)))

	offset := 5
	if len(routeBytes) > 0 {
		copy(buf[offset:], routeBytes)
		offset += len(routeBytes)
	}
	if len(clientBytes) > 0 {
		copy(buf[offset:], clientBytes)
		offset += len(clientBytes)
	}
	if len(p.Payload) > 0 {
		copy(buf[offset:], p.Payload)
	}

	_, err := w.Write(buf)
	return err
}

// ReadPacket reads a packet from an io.Reader (for TCP)
func ReadPacket(r io.Reader) (*Packet, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	p := &Packet{
		Type: header[0],
	}

	routeLen := int(header[1])
	clientLen := int(header[2])
	payloadLen := int(binary.BigEndian.Uint16(header[3:5]))

	if routeLen > 0 {
		routeBytes := make([]byte, routeLen)
		if _, err := io.ReadFull(r, routeBytes); err != nil {
			return nil, err
		}
		p.Route = string(routeBytes)
	}

	if clientLen > 0 {
		clientBytes := make([]byte, clientLen)
		if _, err := io.ReadFull(r, clientBytes); err != nil {
			return nil, err
		}
		p.Client = string(clientBytes)
	}

	if payloadLen > 0 {
		p.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, p.Payload); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// MarshalUDP encodes a packet for UDP transmission
func MarshalUDP(p *Packet, dst []byte) ([]byte, error) {
	routeBytes := []byte(p.Route)
	clientBytes := []byte(p.Client)

	if len(p.Payload) > MaxPayloadSize {
		return nil, ErrPayloadTooBig
	}

	totalLen := 1 + 1 + len(routeBytes) + 1 + len(clientBytes) + len(p.Payload)

	if cap(dst) < totalLen {
		dst = make([]byte, totalLen)
	} else {
		dst = dst[:totalLen]
	}

	i := 0
	dst[i] = p.Type
	i++

	dst[i] = byte(len(routeBytes))
	i++
	copy(dst[i:], routeBytes)
	i += len(routeBytes)

	dst[i] = byte(len(clientBytes))
	i++
	copy(dst[i:], clientBytes)
	i += len(clientBytes)

	copy(dst[i:], p.Payload)
	return dst, nil
}

// UnmarshalUDP decodes a packet from a UDP datagram
func UnmarshalUDP(data []byte) (*Packet, error) {
	if len(data) < 3 {
		return nil, ErrInvalidPacket
	}

	p := &Packet{
		Type: data[0],
	}

	i := 1
	routeLen := int(data[i])
	i++

	if len(data) < i+routeLen+1 {
		return nil, ErrInvalidPacket
	}
	p.Route = string(data[i : i+routeLen])
	i += routeLen

	clientLen := int(data[i])
	i++

	if len(data) < i+clientLen {
		return nil, ErrInvalidPacket
	}
	p.Client = string(data[i : i+clientLen])
	i += clientLen

	p.Payload = data[i:]
	return p, nil
}
