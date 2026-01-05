//go:build !windows

package updater

import (
	"os"
	"os/exec"
	"syscall"
)

// SpawnNew starts a new process with the given executable + args.
func SpawnNew(exe string, args []string) error {
	cmd := exec.Command(exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ()
	return cmd.Start()
}

// ExecReplace replaces the current process image (does not return on success).
func ExecReplace(exe string, args []string) error {
	argv := append([]string{exe}, args...)
	return syscall.Exec(exe, argv, os.Environ())
}
