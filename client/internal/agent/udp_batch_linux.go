//go:build linux

package agent

import (
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr is the structure used by sendmmsg/recvmmsg syscalls.
// This is not exposed by x/sys/unix, so we define it ourselves.
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

// sendmmsg sends multiple packets in a single syscall on Linux.
// This reduces syscall overhead for high-throughput UDP scenarios.
// Returns the number of packets successfully sent and any error.
func sendmmsg(conn *net.UDPConn, packets [][]byte, addrs []*net.UDPAddr) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(packets) != len(addrs) {
		panic("sendmmsg: packets and addrs must have same length")
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var sent int
	var sendErr error

	err = raw.Control(func(fd uintptr) {
		// Prepare mmsghdr structures
		msgs := make([]mmsghdr, len(packets))
		iovecs := make([]unix.Iovec, len(packets))
		var sa4s []sockaddrInet4
		var sa6s []sockaddrInet6

		for i, pkt := range packets {
			// Set up iovec
			iovecs[i] = unix.Iovec{
				Base: &pkt[0],
				Len:  uint64(len(pkt)),
			}

			// Set up sockaddr
			addr := addrs[i]
			if addr == nil {
				// No address - use connected socket
				msgs[i].Hdr.Iov = &iovecs[i]
				msgs[i].Hdr.Iovlen = 1
				continue
			}

			if len(addr.IP) == net.IPv4len || addr.IP.To4() != nil {
				// IPv4
				var sa4 sockaddrInet4
				sa4.Family = unix.AF_INET
				sa4.Port = binary.BigEndian.Uint16([]byte{byte(addr.Port >> 8), byte(addr.Port)})
				copy(sa4.Addr[:], addr.IP.To4())
				sa4s = append(sa4s, sa4)
				msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sa4s[len(sa4s)-1]))
				msgs[i].Hdr.Namelen = uint32(unsafe.Sizeof(sa4))
			} else {
				// IPv6
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

		// Call sendmmsg
		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMMSG,
			fd,
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(len(msgs)),
			unix.MSG_DONTWAIT,
			0, 0,
		)

		if errno != 0 {
			sendErr = errno
			return
		}
		sent = int(n)
	})

	if err != nil {
		return 0, err
	}
	if sendErr != nil {
		return sent, sendErr
	}
	return sent, nil
}

// recvmmsg receives multiple packets in a single syscall on Linux.
// Returns the number of packets received, the actual sizes, and any error.
func recvmmsg(conn *net.UDPConn, buffers [][]byte) (int, []int, []*net.UDPAddr, error) {
	if len(buffers) == 0 {
		return 0, nil, nil, nil
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, nil, nil, err
	}

	var received int
	var sizes []int
	var recvAddrs []*net.UDPAddr
	var recvErr error

	err = raw.Control(func(fd uintptr) {
		msgs := make([]mmsghdr, len(buffers))
		iovecs := make([]unix.Iovec, len(buffers))
		namebufs := make([][128]byte, len(buffers))
		sizes = make([]int, len(buffers))
		recvAddrs = make([]*net.UDPAddr, len(buffers))

		for i, buf := range buffers {
			iovecs[i] = unix.Iovec{
				Base: &buf[0],
				Len:  uint64(len(buf)),
			}

			msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&namebufs[i][0]))
			msgs[i].Hdr.Namelen = 128
			msgs[i].Hdr.Iov = &iovecs[i]
			msgs[i].Hdr.Iovlen = 1
		}

		n, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&msgs[0])),
			uintptr(len(msgs)),
			unix.MSG_DONTWAIT,
			0, 0,
		)

		if errno != 0 && errno != unix.EAGAIN && errno != unix.EWOULDBLOCK {
			recvErr = errno
			return
		}

		received = int(n)
		for i := 0; i < received; i++ {
			sizes[i] = int(msgs[i].Len)
			// Parse sockaddr from namebuf
			recvAddrs[i] = parseSockaddr(namebufs[i][:msgs[i].Hdr.Namelen])
		}
	})

	if err != nil {
		return 0, nil, nil, err
	}
	return received, sizes, recvAddrs, recvErr
}

// parseSockaddr parses a raw sockaddr into a net.UDPAddr.
func parseSockaddr(b []byte) *net.UDPAddr {
	if len(b) < 2 {
		return nil
	}
	family := *(*uint16)(unsafe.Pointer(&b[0]))
	switch family {
	case unix.AF_INET:
		if len(b) < 16 {
			return nil
		}
		port := binary.BigEndian.Uint16(b[2:4])
		ip := net.IPv4(b[4], b[5], b[6], b[7])
		return &net.UDPAddr{IP: ip, Port: int(port)}
	case unix.AF_INET6:
		if len(b) < 28 {
			return nil
		}
		port := binary.BigEndian.Uint16(b[2:4])
		ip := make(net.IP, 16)
		copy(ip, b[8:24])
		return &net.UDPAddr{IP: ip, Port: int(port)}
	}
	return nil
}
