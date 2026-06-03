//go:build linux

package netutil

import (
	"syscall"
	"testing"
	"time"
)

// TestSetTCPUserTimeoutAppliesValueLinux verifies the TCP_USER_TIMEOUT socket
// option is actually written to the kernel by reading it back with getsockopt.
// This is the regression guard ensuring dead-peer reaping is wired through to
// the OS, not just silently dropped.
func TestSetTCPUserTimeoutAppliesValueLinux(t *testing.T) {
	client, _ := tcpConnPair(t)

	const want = 7 * time.Second
	if err := SetTCPUserTimeout(client, want); err != nil {
		t.Fatalf("SetTCPUserTimeout: %v", err)
	}

	tcpConn := UnwrapTCPConn(client)
	if tcpConn == nil {
		t.Fatal("UnwrapTCPConn returned nil")
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var (
		got    int
		getErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		got, getErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout)
	})
	if ctrlErr != nil {
		t.Fatalf("raw.Control: %v", ctrlErr)
	}
	if getErr != nil {
		t.Fatalf("GetsockoptInt: %v", getErr)
	}

	wantMs := int(want / time.Millisecond)
	if got != wantMs {
		t.Fatalf("TCP_USER_TIMEOUT = %d ms, want %d ms", got, wantMs)
	}
}

// TestTuneDeadPeerDetectionSetsUserTimeoutLinux verifies the bundled tuning
// helper applies a non-zero TCP_USER_TIMEOUT, so callers using the convenience
// wrapper get the same protection.
func TestTuneDeadPeerDetectionSetsUserTimeoutLinux(t *testing.T) {
	client, _ := tcpConnPair(t)
	TuneDeadPeerDetection(client)

	tcpConn := UnwrapTCPConn(client)
	if tcpConn == nil {
		t.Fatal("UnwrapTCPConn returned nil")
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var (
		got    int
		getErr error
	)
	if ctrlErr := raw.Control(func(fd uintptr) {
		got, getErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout)
	}); ctrlErr != nil {
		t.Fatalf("raw.Control: %v", ctrlErr)
	}
	if getErr != nil {
		t.Fatalf("GetsockoptInt: %v", getErr)
	}
	if got != int(deadPeerUserTimeout/time.Millisecond) {
		t.Fatalf("TCP_USER_TIMEOUT = %d ms, want %d ms", got, int(deadPeerUserTimeout/time.Millisecond))
	}
}
