//go:build !windows

package updater

import (
	"os"
	"os/exec"
	"syscall"
)

// ExecReplace replaces the current process with a new instance of the binary.
// On Unix, it uses execve(2) to replace the process image.
func ExecReplace(bin string, args []string) error {
	// On Unix, use execve to replace the process image
	path, err := exec.LookPath(bin)
	if err != nil {
		path = bin
	}
	return syscall.Exec(path, args, os.Environ())
}
