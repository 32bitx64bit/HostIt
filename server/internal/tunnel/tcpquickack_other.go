//go:build !linux

package tunnel

import "net"

func setTCPQuickACK(conn net.Conn, on bool) {}
