// Package module provides utilities for detecting the module directory.
package module

import (
	"os"
	"path/filepath"
	"strings"
)

// DetectModuleDir returns the directory containing the module's build.sh file.
// It checks:
// 1. Current working directory
// 2. Parent of bin directory if running from ./bin/<binary>
// 3. Directory alongside the config file
// 4. "." as fallback
func DetectModuleDir(configPath string) string {
	// Prefer current working directory if build.sh is present.
	if wd, err := os.Getwd(); err == nil && wd != "" {
		if fileExists(filepath.Join(wd, "build.sh")) {
			return wd
		}
	}
	// If we're running from ./bin/<binary>, prefer the parent dir.
	if exe, err := os.Executable(); err == nil && exe != "" {
		exeDir := filepath.Dir(exe)
		if filepath.Base(exeDir) == "bin" {
			parent := filepath.Dir(exeDir)
			if fileExists(filepath.Join(parent, "build.sh")) {
				return parent
			}
		}
	}
	// Fallback: alongside config.
	if strings.TrimSpace(configPath) != "" {
		return filepath.Dir(configPath)
	}
	return "."
}

// fileExists reports whether path exists and is not a directory.
func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
