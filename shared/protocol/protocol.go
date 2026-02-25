package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"unsafe"
)

const (
	TypeRegister byte = 1
	TypeData     byte = 2
	TypePing     byte = 3
	TypePong     byte = 4
	TypeHello    byte = 5
	TypeConnect  byte = 6
)

var (
	ErrInvalidPacket = errors.New("invalid packet")
	ErrPayloadTooBig = errors.New("payload too big")
)

const MaxPayloadSize = 64 * 1024 // 64KB

type Packet struct {
	Type    byte
	Route   string
	Client  string
	Payload []byte
}

func WritePacket(w io.Writer, p *Packet) error {
	if len(p.Payload) > MaxPayloadSize {
		return ErrPayloadTooBig
	}

	totalLen := 5 + len(p.Route) + len(p.Client) + len(p.Payload)
	buf := make([]byte, totalLen)

	buf[0] = p.Type
	buf[1] = byte(len(p.Route))
	buf[2] = byte(len(p.Client))
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(p.Payload)))

	offset := 5
	if len(p.Route) > 0 {
		copy(buf[offset:], p.Route)
		offset += len(p.Route)
	}
	if len(p.Client) > 0 {
		copy(buf[offset:], p.Client)
		offset += len(p.Client)
	}
	if len(p.Payload) > 0 {
		copy(buf[offset:], p.Payload)
	}

	_, err := w.Write(buf)
	return err
}

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

func MarshalUDP(p *Packet, dst []byte) ([]byte, error) {
	if len(p.Payload) > MaxPayloadSize {
		return nil, ErrPayloadTooBig
	}

	totalLen := 1 + 1 + len(p.Route) + 1 + len(p.Client) + len(p.Payload)

	if cap(dst) < totalLen {
		dst = make([]byte, totalLen)
	} else {
		dst = dst[:totalLen]
	}

	i := 0
	dst[i] = p.Type
	i++

	dst[i] = byte(len(p.Route))
	i++
	copy(dst[i:], p.Route)
	i += len(p.Route)

	dst[i] = byte(len(p.Client))
	i++
	copy(dst[i:], p.Client)
	i += len(p.Client)

	copy(dst[i:], p.Payload)
	return dst, nil
}

func UnmarshalUDP(data []byte) (*Packet, error) {
	p := &Packet{}
	err := UnmarshalUDPTo(data, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func UnmarshalUDPTo(data []byte, p *Packet) error {
	if len(data) < 3 {
		return ErrInvalidPacket
	}

	p.Type = data[0]

	i := 1
	routeLen := int(data[i])
	i++

	if len(data) < i+routeLen+1 {
		return ErrInvalidPacket
	}
	p.Route = unsafe.String(unsafe.SliceData(data[i:i+routeLen]), routeLen)
	i += routeLen

	clientLen := int(data[i])
	i++

	if len(data) < i+clientLen {
		return ErrInvalidPacket
	}
	p.Client = unsafe.String(unsafe.SliceData(data[i:i+clientLen]), clientLen)
	i += clientLen

	p.Payload = data[i:]
	return nil
}
