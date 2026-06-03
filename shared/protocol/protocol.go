package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"unsafe"

	"hostit/shared/netutil"
)

const (
	TypeRegister          byte = 1
	TypeData              byte = 2
	TypePing              byte = 3
	TypePong              byte = 4
	TypeHello             byte = 5
	TypeConnect           byte = 6
	TypeEmailProbeRequest byte = 7
	TypeEmailProbeResult  byte = 8
	TypeRouteRequest      byte = 9
	TypeRouteResponse     byte = 10
	TypeRouteConfirm      byte = 11
	TypeRouteAck          byte = 12
	TypeRouteRemove       byte = 13
	TypeRouteRemoveAck    byte = 14
	TypeRouteUpdate       byte = 15
	TypeRouteUpdateAck    byte = 16
)

const RouteMailOutboundTCP = "hostit_mail_outbound"

var (
	ErrInvalidPacket = errors.New("invalid packet")
	ErrPayloadTooBig = errors.New("payload too big")
	ErrFieldTooLong  = errors.New("route or client field too long")
)

const MaxPayloadSize = 64*1024 - 1 // Maximum payload frameable in uint16 length field.

const maxPacketBufSize = 5 + 255 + 255 + MaxPayloadSize

type Packet struct {
	Type    byte
	Route   string
	Client  string
	Payload []byte
}

var (
	packetBufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, maxPacketBufSize)
			return &b
		},
	}
	headerBufPool = sync.Pool{
		New: func() interface{} {
			var b [5]byte
			return &b
		},
	}
)

type UDPScratch struct {
	buf []byte
}

func (s *UDPScratch) resetFor(n int) {
	if cap(s.buf) < n {
		s.buf = make([]byte, n, n)
	} else {
		s.buf = s.buf[:n]
	}
}

func WritePacket(w io.Writer, p *Packet) error {
	if len(p.Payload) > MaxPayloadSize {
		return ErrPayloadTooBig
	}
	if len(p.Route) > 255 || len(p.Client) > 255 {
		return ErrFieldTooLong
	}

	totalLen := 5 + len(p.Route) + len(p.Client) + len(p.Payload)

	bufPtr := packetBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:totalLen]

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

	_, err := netutil.WriteAll(w, buf)
	packetBufPool.Put(bufPtr)
	return err
}

// bytesToString aliases the slice's backing memory; safe because the
// slice is read once and never modified.
func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func ReadPacket(r io.Reader) (*Packet, error) {
	p := &Packet{}
	if err := ReadPacketTo(r, p); err != nil {
		return nil, err
	}
	return p, nil
}

// ReadPacketTo fills p in place from a control-plane TCP frame. Callers
// can reuse the destination across iterations to skip the per-packet
// &Packet{} allocation. Fields are overwritten in place; callers must
// not retain references to Route, Client, or Payload across calls.
func ReadPacketTo(r io.Reader, p *Packet) error {
	headerPtr := headerBufPool.Get().(*[5]byte)
	header := headerPtr[:]
	if _, err := io.ReadFull(r, header); err != nil {
		headerBufPool.Put(headerPtr)
		return err
	}

	p.Type = header[0]

	routeLen := int(header[1])
	clientLen := int(header[2])
	payloadLen := int(binary.BigEndian.Uint16(header[3:5]))

	headerBufPool.Put(headerPtr)

	if payloadLen > MaxPayloadSize {
		return ErrPayloadTooBig
	}

	if routeLen > 0 {
		routeBytes := make([]byte, routeLen)
		if _, err := io.ReadFull(r, routeBytes); err != nil {
			return err
		}
		p.Route = bytesToString(routeBytes)
	} else {
		p.Route = ""
	}

	if clientLen > 0 {
		clientBytes := make([]byte, clientLen)
		if _, err := io.ReadFull(r, clientBytes); err != nil {
			return err
		}
		p.Client = bytesToString(clientBytes)
	} else {
		p.Client = ""
	}

	if payloadLen > 0 {
		if cap(p.Payload) >= payloadLen {
			p.Payload = p.Payload[:payloadLen]
		} else {
			p.Payload = make([]byte, payloadLen)
		}
		if _, err := io.ReadFull(r, p.Payload); err != nil {
			return err
		}
	} else {
		p.Payload = nil
	}

	return nil
}

func MarshalUDP(p *Packet, dst []byte) ([]byte, error) {
	if len(p.Payload) > MaxPayloadSize {
		return nil, ErrPayloadTooBig
	}
	if len(p.Route) > 255 || len(p.Client) > 255 {
		return nil, ErrFieldTooLong
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
	if p.Type < TypeRegister || p.Type > TypeRouteUpdateAck {
		return ErrInvalidPacket
	}

	i := 1
	routeLen := int(data[i])
	i++

	if len(data) < i+routeLen+1 {
		return ErrInvalidPacket
	}

	p.Route = string(data[i : i+routeLen])
	i += routeLen

	clientLen := int(data[i])
	i++

	if len(data) < i+clientLen {
		return ErrInvalidPacket
	}
	p.Client = string(data[i : i+clientLen])
	i += clientLen

	p.Payload = data[i:]
	return nil
}
