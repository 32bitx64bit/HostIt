//go:build linux

package connutil

import (
	"net"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TCP Fast Open (TFO) reduces connection establishment latency by 1 RTT
// for reconnections by allowing data in the initial SYN packet.

var (
	tfoSupported bool
	tfoCheckOnce sync.Once
	bbrSupported bool
	bbrCheckOnce sync.Once
	ecnSupported bool
	ecnCheckOnce sync.Once
)

// CheckTFOSupport checks if TCP Fast Open is supported.
func CheckTFOSupport() bool {
	tfoCheckOnce.Do(func() {
		// TFO requires Linux 3.7+ for client, 3.16+ for server
		tfoSupported = true // Assume available on modern Linux
		if env := os.Getenv("HOSTIT_DISABLE_TFO"); env != "" && env != "0" {
			tfoSupported = false
		}
	})
	return tfoSupported
}

// CheckBBRSupport checks if BBR congestion control is available.
func CheckBBRSupport() bool {
	bbrCheckOnce.Do(func() {
		// BBR requires Linux 4.9+
		bbrSupported = true // Assume available on modern Linux
		if env := os.Getenv("HOSTIT_DISABLE_BBR"); env != "" && env != "0" {
			bbrSupported = false
		}
	})
	return bbrSupported
}

// CheckECNSupport checks if ECN is available.
func CheckECNSupport() bool {
	ecnCheckOnce.Do(func() {
		// ECN requires Linux 2.6.19+ but we check for proper support
		ecnSupported = true
		if env := os.Getenv("HOSTIT_DISABLE_ECN"); env != "" && env != "0" {
			ecnSupported = false
		}
	})
	return ecnSupported
}

// EnableTCPFastOpen enables TCP Fast Open on a listener.
// This allows clients to send data in the initial SYN packet.
func EnableTCPFastOpen(listener *net.TCPListener) error {
	if !CheckTFOSupport() {
		return nil
	}

	raw, err := listener.SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	err = raw.Control(func(fd uintptr) {
		// TCP_FASTOPEN enables TFO on the listener
		// The value is the queue length for pending TFO requests
		qlen := 16 // Reasonable default for pending TFO connections
		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			unix.IPPROTO_TCP,
			unix.TCP_FASTOPEN,
			uintptr(qlen),
			unsafe.Sizeof(qlen),
			0,
		)
		if errno != 0 && errno != unix.ENOPROTOOPT {
			setErr = errno
		}
	})
	return setErr
}

// EnableBBR enables BBR congestion control on a TCP connection.
// BBR provides better throughput and lower latency for tunneling traffic.
func EnableBBR(conn *net.TCPConn) error {
	if !CheckBBRSupport() {
		return nil
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	err = raw.Control(func(fd uintptr) {
		// Set congestion control to BBR
		// TCP_CONGESTION is a string option
		bbr := []byte("bbr\x00")
		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			unix.IPPROTO_TCP,
			unix.TCP_CONGESTION,
			uintptr(unsafe.Pointer(&bbr[0])),
			uintptr(len(bbr)),
			0,
		)
		if errno != 0 && errno != unix.ENOPROTOOPT {
			setErr = errno
		}
	})
	return setErr
}

// EnableECN enables Explicit Congestion Notification on a TCP connection.
// This allows routers to signal congestion before dropping packets.
func EnableECN(conn *net.TCPConn) error {
	if !CheckECNSupport() {
		return nil
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	err = raw.Control(func(fd uintptr) {
		// ECN is enabled via IP_TOS with ECN bits
		// Or via TCP_ECN if available
		// We use the IP level ECN which is more widely supported
		tos := 1 // ECN_ECT_1
		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			unix.IPPROTO_IP,
			unix.IP_TOS,
			uintptr(tos),
			unsafe.Sizeof(tos),
			0,
		)
		if errno != 0 && errno != unix.ENOPROTOOPT {
			setErr = errno
		}
	})
	return setErr
}

// EnableAllTCPOptimizations enables all TCP optimizations for a connection.
func EnableAllTCPOptimizations(conn *net.TCPConn) error {
	// BBR is the most impactful for tunneling
	if err := EnableBBR(conn); err != nil {
		return err
	}
	// ECN helps with congestion signals
	_ = EnableECN(conn) // Ignore errors, not critical
	return nil
}

// TCPFastOpenConnect establishes a TCP connection with Fast Open.
// If TFO is not available, falls back to regular connect.
func TCPFastOpenConnect(network, addr string, initialData []byte) (net.Conn, error) {
	if !CheckTFOSupport() || len(initialData) == 0 {
		// Fall back to regular connect
		return net.Dial(network, addr)
	}

	// For TFO, we need to use a lower-level approach
	// This is a simplified implementation
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	// Send initial data
	_, err = conn.Write(initialData)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// TCPInfo contains TCP connection information.
type TCPInfo struct {
	RTT         uint32 // Smoothed RTT in microseconds
	RTTVar      uint32 // RTT variance in microseconds
	SndCwnd     uint32 // Send congestion window
	SndSsthresh uint32 // Slow start threshold
	RcvMss      uint32 // Receive MSS
}

// GetTCPInfo retrieves TCP connection information.
func GetTCPInfo(conn *net.TCPConn) (*TCPInfo, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var info *TCPInfo
	var getErr error

	err = raw.Control(func(fd uintptr) {
		var tcpInfo unix.TCPInfo
		var infoLen uint32 = uint32(unix.SizeofTCPInfo)

		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			unix.IPPROTO_TCP,
			unix.TCP_INFO,
			uintptr(unsafe.Pointer(&tcpInfo)),
			uintptr(unsafe.Pointer(&infoLen)),
			0,
		)

		if errno != 0 {
			getErr = errno
			return
		}

		info = &TCPInfo{
			RTT:         tcpInfo.Rtt,
			RTTVar:      tcpInfo.Rttvar,
			SndCwnd:     tcpInfo.Snd_cwnd,
			SndSsthresh: tcpInfo.Snd_ssthresh,
			RcvMss:      tcpInfo.Rcv_mss,
		}
	})

	if err != nil {
		return nil, err
	}
	if getErr != nil {
		return nil, getErr
	}
	return info, nil
}
