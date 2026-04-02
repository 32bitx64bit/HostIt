//go:build !windows

package updater

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func ExecReplace(bin string, args []string) error {
	path, err := exec.LookPath(bin)
	if err != nil {
		path = bin
	}
	argv := make([]string, 0, len(args)+1)
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" || strings.HasPrefix(strings.TrimSpace(args[0]), "-") {
		argv = append(argv, path)
	}
	argv = append(argv, args...)
	if len(argv) == 0 {
		argv = []string{path}
	}
	return syscall.Exec(path, argv, os.Environ())
}
