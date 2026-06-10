//go:build unix

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func sendSIGTERM(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

func notifyContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}
