//go:build linux

package udputil

import (
	"encoding/binary"
	"net"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// UDP GSO (Generic Segmentation Offload) allows the kernel to split
// large UDP payloads into multiple MTU-sized packets, reducing syscall
// overhead by 10-100x for high-throughput scenarios.

const (
	// UDP_SEGMENT is the socket option for GSO (Linux 4.18+)
	UDP_SEGMENT = 103
	// UDP_GRO is the socket option for GRO (Linux 5.3+)
	UDP_GRO = 104
)

var (
	gsoSupported    bool
	groSupported    bool
	gsoGROCheckOnce sync.Once
	gsoSegmentSize  int = 0 // 0 means use default (MTU - headers)
)

// CheckGSOSupport checks if UDP GSO is supported on this system.
func CheckGSOSupport() bool {
	gsoGROCheckOnce.Do(func() {
		// Check kernel version - GSO requires 4.18+, GRO requires 5.3+
		var uname unix.Utsname
		if err := unix.Uname(&uname); err == nil {
			// Parse major.minor from release string
			release := string(uname.Release[:])
			var major, minor int
			for i := 0; i < len(release) && release[i] >= '0' && release[i] <= '9'; i++ {
				major = major*10 + int(release[i]-'0')
			}
			dotIdx := 0
			for i := 0; i < len(release); i++ {
				if release[i] == '.' {
					dotIdx = i + 1
					break
				}
			}
			for i := dotIdx; i < len(release) && release[i] >= '0' && release[i] <= '9'; i++ {
				minor = minor*10 + int(release[i]-'0')
			}

			// GSO: 4.18+
			if major > 4 || (major == 4 && minor >= 18) {
				gsoSupported = true
			}
			// GRO: 5.3+
			if major > 5 || (major == 5 && minor >= 3) {
				groSupported = true
			}
		}

		// Allow override via environment
		if env := os.Getenv("HOSTIT_DISABLE_GSO"); env != "" && env != "0" {
			gsoSupported = false
		}
		if env := os.Getenv("HOSTIT_DISABLE_GRO"); env != "" && env != "0" {
			groSupported = false
		}
	})
	return gsoSupported
}

// CheckGROSupport checks if UDP GRO is supported on this system.
func CheckGROSupport() bool {
	CheckGSOSupport()
	return groSupported
}

// IsGSOEnabled returns true if GSO is available and enabled.
func IsGSOEnabled() bool {
	return CheckGSOSupport()
}

// IsGROEnabled returns true if GRO is available and enabled.
func IsGROEnabled() bool {
	return CheckGROSupport()
}

// SetGSOSegmentSize sets the segment size for GSO.
// If 0, uses the default (MTU - IP/UDP headers = ~1452 for IPv4 over Ethernet).
func SetGSOSegmentSize(size int) {
	gsoSegmentSize = size
}

// EnableGSO enables UDP GSO on a socket.
func EnableGSO(conn *net.UDPConn) error {
	if !CheckGSOSupport() {
		return nil // Not supported, silently ignore
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	err = raw.Control(func(fd uintptr) {
		// Enable UDP_SEGMENT capability
		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			unix.IPPROTO_UDP,
			UDP_SEGMENT,
			uintptr(unsafe.Pointer(&gsoSegmentSize)),
			unsafe.Sizeof(gsoSegmentSize),
			0,
		)
		if errno != 0 && errno != unix.ENOPROTOOPT {
			setErr = errno
		}
	})
	if err != nil {
		return err
	}
	return setErr
}

// EnableGRO enables UDP GRO on a socket.
func EnableGRO(conn *net.UDPConn) error {
	if !CheckGROSupport() {
		return nil // Not supported, silently ignore
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	enabled := 1
	err = raw.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			unix.IPPROTO_UDP,
			UDP_GRO,
			uintptr(unsafe.Pointer(&enabled)),
			unsafe.Sizeof(enabled),
			0,
		)
		if errno != 0 && errno != unix.ENOPROTOOPT {
			setErr = errno
		}
	})
	if err != nil {
		return err
	}
	return setErr
}

// SendWithGSO sends a large payload using GSO segmentation.
// The kernel will split the payload into segments of segmentSize bytes.
// Returns the number of segments sent and any error.
func SendWithGSO(conn *net.UDPConn, data []byte, segmentSize int, addr *net.UDPAddr) (int, error) {
	if !CheckGSOSupport() {
		// Fallback to regular send
		_, err := conn.WriteToUDP(data, addr)
		return 1, err
	}

	if segmentSize <= 0 {
		segmentSize = 1452 // Default: 1500 MTU - 20 IP - 8 UDP - 20 (safety margin)
	}

	// Calculate number of segments
	numSegments := (len(data) + segmentSize - 1) / segmentSize

	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var sendErr error

	err = raw.Control(func(fd uintptr) {
		// Prepare iovec
		iov := unix.Iovec{
			Base: &data[0],
			Len:  uint64(len(data)),
		}

		// Prepare msghdr
		var name unsafe.Pointer
		var namelen uint32
		var sa4 sockaddrInet4
		var sa6 sockaddrInet6

		if addr != nil {
			if len(addr.IP) == net.IPv4len || addr.IP.To4() != nil {
				sa4.Family = unix.AF_INET
				sa4.Port = binary.BigEndian.Uint16([]byte{byte(addr.Port >> 8), byte(addr.Port)})
				copy(sa4.Addr[:], addr.IP.To4())
				name = unsafe.Pointer(&sa4)
				namelen = uint32(unsafe.Sizeof(sa4))
			} else {
				sa6.Family = unix.AF_INET6
				sa6.Port = binary.BigEndian.Uint16([]byte{byte(addr.Port >> 8), byte(addr.Port)})
				copy(sa6.Addr[:], addr.IP)
				name = unsafe.Pointer(&sa6)
				namelen = uint32(unsafe.Sizeof(sa6))
			}
		}

		// Prepare cmsg for GSO segment size
		// We need to pass UDP_SEGMENT in the control message
		cmsgBuf := make([]byte, unix.CmsgSpace(4))
		cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&cmsgBuf[0]))
		cmsg.Level = unix.IPPROTO_UDP
		cmsg.Type = UDP_SEGMENT
		cmsg.SetLen(unix.CmsgLen(4))
		*(*uint32)(unsafe.Pointer(&cmsgBuf[unix.CmsgLen(0)])) = uint32(segmentSize)

		msg := unix.Msghdr{
			Name:       (*byte)(name),
			Namelen:    namelen,
			Iov:        &iov,
			Iovlen:     1,
			Control:    &cmsgBuf[0],
			Controllen: uint64(len(cmsgBuf)),
		}

		// Use sendmsg
		n, _, errno := unix.Syscall6(
			unix.SYS_SENDMSG,
			fd,
			uintptr(unsafe.Pointer(&msg)),
			0, // flags
			0, 0, 0,
		)

		if errno != 0 {
			sendErr = errno
		}
		_ = n // bytes sent, we return segments instead
	})

	if err != nil {
		return 0, err
	}
	if sendErr != nil {
		return 0, sendErr
	}

	// sent is the number of bytes written, not segments
	// The kernel sends the appropriate number of segments
	return numSegments, nil
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

// RecvWithGRO receives packets with GRO enabled.
// Returns the combined payload and the source address.
func RecvWithGRO(conn *net.UDPConn, buf []byte) (int, *net.UDPAddr, error) {
	// With GRO enabled, the kernel combines packets before delivery
	// We just use normal ReadFromUDP, but may receive larger payloads
	n, addr, err := conn.ReadFromUDP(buf)
	return n, addr, err
}

// GSOStats tracks GSO/GRO statistics.
type GSOStats struct {
	GSOEnabled       bool
	GROEnabled       bool
	SegmentsSent     uint64
	BytesSent        uint64
	GROPacketsMerged uint64
}

// GetGSOStats returns current GSO/GRO statistics.
func GetGSOStats() GSOStats {
	return GSOStats{
		GSOEnabled: IsGSOEnabled(),
		GROEnabled: IsGROEnabled(),
	}
}
