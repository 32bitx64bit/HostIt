package main

import "os/exec"

func systemctlAvailable() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}
