package main

import "os"

func runningUnderSystemd() bool {
	// Common environment variables systemd sets for services.
	if v := os.Getenv("INVOCATION_ID"); v != "" {
		return true
	}
	if v := os.Getenv("JOURNAL_STREAM"); v != "" {
		return true
	}
	if v := os.Getenv("SYSTEMD_EXEC_PID"); v != "" {
		return true
	}
	return false
}
