//go:build unix

package main

import "syscall"

func sendSIGTERM(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}
