//go:build !linux

package main

import "fmt"

func agentSystemdIdentityLines(moduleDir string) string {
	return ""
}

func agentSystemdUnitContent(moduleDir string) string {
	return ""
}

func ensureAgentSystemdEnvFile() error {
	return nil
}

func syncInstalledAgentSystemdUnit(moduleDir string) error {
	return fmt.Errorf("systemd is not supported on this platform")
}
