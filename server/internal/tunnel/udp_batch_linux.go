//go:build linux

package tunnel

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr is the structure used by sendmmsg/recvmmsg syscalls.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte // padding
}

// sockaddrInet4 is the raw sockaddr_in structure for IPv4.
type sockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	_      [8]byte // padding
}

// sockaddrInet6 is the raw sockaddr_in6 structure for IPv6.
type sockaddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	Scope_id uint32
}

// sendmmsgWriteTo sends multiple packets to different destinations in a single
// syscall on Linux. This dramatically reduces syscall overhead for high-throughput
// streaming scenarios. Returns the number of packets successfully sent.
func sendmmsgWriteTo(conn *net.UDPConn, packets [][]byte, addrs []*net.UDPAddr) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(packets) != len(addrs) {
		panic("sendmmsgWriteTo: packets and addrs must have same length")
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var sent int
	var sendErr error

	err = raw.Control(func(fd uintptr) {
		msgs := make([]mmsghdr, len(packets))
		iovecs := make([]unix.Iovec, len(packets))
		// Pre-allocate sockaddr slices with full capacity to prevent
		// reallocation during append. Without this, append may create a
		// new backing array, making all previous unsafe.Pointer refs in
		// msgs[j].Hdr.Name dangling — the kernel would send to garbage
		// addresses silently.
		sa4s := make([]sockaddrInet4, 0, len(packets))
		sa6s := make([]sockaddrInet6, 0, len(packets))

		for i, pkt := range packets {
			// Guard against zero-length packets — &pkt[0] panics on empty slice
			if len(pkt) == 0 {
				continue
			}
			iovecs[i] = unix.Iovec{
				Base: &pkt[0],
				Len:  uint64(len(pkt)),
			}

			addr := addrs[i]
			if addr == nil {
				msgs[i].Hdr.Iov = &iovecs[i]
				msgs[i].Hdr.Iovlen = 1
				continue
			}

			if len(addr.IP) == net.IPv4len || addr.IP.To4() != nil {
				var sa4 sockaddrInet4
				sa4.Family = unix.AF_INET
				sa4.Port = binary.BigEndian.Uint16([]byte{byte(addr.Port >> 8), byte(addr.Port)})
				copy(sa4.Addr[:], addr.IP.To4())
				sa4s = append(sa4s, sa4)
				msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sa4s[len(sa4s)-1]))
				msgs[i].Hdr.Namelen = uint32(unsafe.Sizeof(sa4))
			} else {
				var sa6 sockaddrInet6
				sa6.Family = unix.AF_INET6
				sa6.Port = binary.BigEndian.Uint16([]byte{byte(addr.Port >> 8), byte(addr.Port)})
				copy(sa6.Addr[:], addr.IP)
				sa6s = append(sa6s, sa6)
				msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sa6s[len(sa6s)-1]))
				msgs[i].Hdr.Namelen = uint32(unsafe.Sizeof(sa6))
			}
			msgs[i].Hdr.Iov = &iovecs[i]
			msgs[i].Hdr.Iovlen = 1
		}

		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			fd,
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(len(msgs)),
			unix.MSG_DONTWAIT,
			0, 0,
		)

		sent = int(n)
		if errno != 0 {
			sendErr = errno
			return
		}
	})

	if err != nil {
		return 0, err
	}
	if sendErr != nil {
		return sent, sendErr
	}
	return sent, nil
}

// sendmmsgBatch sends multiple packets on a connected socket in a single syscall.
func sendmmsgBatch(conn *net.UDPConn, packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	addrs := make([]*net.UDPAddr, len(packets))
	return sendmmsgWriteTo(conn, packets, addrs)
}

// sendmmsgPacketConn sends multiple packets via a PacketConn (unconnected socket)
// to different addresses using sendmmsg. Falls back to individual WriteTo on error.
func sendmmsgPacketConn(pc net.PacketConn, packets [][]byte, addrs []net.Addr) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}

	// Try to unwrap to *net.UDPConn for sendmmsg
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		// Fallback to individual sends
		return sendIndividual(pc, packets, addrs)
	}

	// Convert net.Addr to *net.UDPAddr
	udpAddrs := make([]*net.UDPAddr, len(addrs))
	for i, a := range addrs {
		if ua, ok := a.(*net.UDPAddr); ok {
			udpAddrs[i] = ua
		} else {
			// Can't use sendmmsg if any address isn't a UDPAddr
			return sendIndividual(pc, packets, addrs)
		}
	}

	return sendmmsgWriteTo(uc, packets, udpAddrs)
}
