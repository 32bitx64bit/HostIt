package module

import (
	"os"
	"path/filepath"
	"strings"
)

func DetectModuleDir(configPath string) string {
	if wd, err := os.Getwd(); err == nil && wd != "" {
		if fileExists(filepath.Join(wd, "build.sh")) {
			return wd
		}
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		exeDir := filepath.Dir(exe)
		if filepath.Base(exeDir) == "bin" {
			parent := filepath.Dir(exeDir)
			if fileExists(filepath.Join(parent, "build.sh")) {
				return parent
			}
		}
	}
	if strings.TrimSpace(configPath) != "" {
		return filepath.Dir(configPath)
	}
	return "."
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
