package updater

import (
	"os"
	"os/exec"
)

// ExecReplace replaces the current process with a new instance of the binary.
// On Windows, we spawn a new process and exit the current one.
func ExecReplace(bin string, args []string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
