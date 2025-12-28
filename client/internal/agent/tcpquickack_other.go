//go:build !linux

package agent

import "net"

func setTCPQuickACK(conn net.Conn, on bool) {}
