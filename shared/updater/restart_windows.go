//go:build windows

package updater

import (
	"errors"
)

func SpawnNew(exe string, args []string) error {
	return errors.New("SpawnNew not implemented on windows")
}

func ExecReplace(exe string, args []string) error {
	return errors.New("ExecReplace not implemented on windows")
}
