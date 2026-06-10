//go:build windows

package main

import "os"

func sendSIGTERM(pid int) error {
	os.Exit(1)
	return nil
}
