//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"
)

func sendSIGTERM(pid int) error {
	os.Exit(1)
	return nil
}

func notifyContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt)
}
