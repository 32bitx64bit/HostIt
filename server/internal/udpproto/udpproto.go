package udpproto

import (
	"encoding/binary"
)

const (
	MsgReg  byte = 1
	MsgData byte = 2
)

func EncodeReg(token string) []byte {
	b := make([]byte, 1+2+len(token))
	b[0] = MsgReg
	binary.BigEndian.PutUint16(b[1:3], uint16(len(token)))
	copy(b[3:], token)
	return b
}

func DecodeReg(b []byte) (token string, ok bool) {
	if len(b) < 3 || b[0] != MsgReg {
		return "", false
	}
	n := int(binary.BigEndian.Uint16(b[1:3]))
	if n < 0 || len(b) != 3+n {
		return "", false
	}
	return string(b[3:]), true
}

func EncodeData(route string, client string, payload []byte) []byte {
	rb := []byte(route)
	cb := []byte(client)
	if len(rb) > 255 {
		rb = rb[:255]
	}
	if len(cb) > 65535 {
		cb = cb[:65535]
	}
	b := make([]byte, 1+1+len(rb)+2+len(cb)+len(payload))
	b[0] = MsgData
	b[1] = byte(len(rb))
	o := 2
	copy(b[o:], rb)
	o += len(rb)
	binary.BigEndian.PutUint16(b[o:o+2], uint16(len(cb)))
	o += 2
	copy(b[o:], cb)
	o += len(cb)
	copy(b[o:], payload)
	return b
}

func DecodeData(b []byte) (route string, client string, payload []byte, ok bool) {
	if len(b) < 1+1+2 || b[0] != MsgData {
		return "", "", nil, false
	}
	rn := int(b[1])
	o := 2
	if rn < 0 || len(b) < o+rn+2 {
		return "", "", nil, false
	}
	route = string(b[o : o+rn])
	o += rn
	cn := int(binary.BigEndian.Uint16(b[o : o+2]))
	o += 2
	if cn < 0 || len(b) < o+cn {
		return "", "", nil, false
	}
	client = string(b[o : o+cn])
	o += cn
	payload = b[o:]
	return route, client, payload, true
}
