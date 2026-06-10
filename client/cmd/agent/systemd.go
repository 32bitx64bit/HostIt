//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func agentSystemdIdentityLines(moduleDir string) string {
	info, err := os.Stat(moduleDir)
	if err != nil {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	usr, err := user.LookupId(fmt.Sprintf("%d", stat.Uid))
	if err != nil || strings.TrimSpace(usr.Username) == "" {
		return ""
	}
	grp, err := user.LookupGroupId(fmt.Sprintf("%d", stat.Gid))
	if err != nil || strings.TrimSpace(grp.Name) == "" {
		return fmt.Sprintf("User=%s\n", usr.Username)
	}
	return fmt.Sprintf("User=%s\nGroup=%s\n", usr.Username, grp.Name)
}

func agentSystemdUnitContent(moduleDir string) string {
	moduleDir = strings.TrimSpace(moduleDir)
	// Reject paths containing shell metacharacters or newlines
	if strings.ContainsAny(moduleDir, "\n\r$`&|;<\x00") {
		moduleDir = "/tmp/invalid-path"
	}
	identity := agentSystemdIdentityLines(moduleDir)
	return fmt.Sprintf(`[Unit]
Description=HostIt Tunnel Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
%sWorkingDirectory=%s
EnvironmentFile=-%s

ExecStartPre=/bin/sh -c "test -x ./bin/tunnel-agent || (echo Missing ./bin/tunnel-agent. Run ./build.sh once as your user. >&2; exit 1)"
ExecStart=/bin/sh %q/client.sh

Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`, identity, moduleDir, agentSystemdEnvPath, moduleDir)
}

func ensureAgentSystemdEnvFile() error {
	if _, err := os.Stat(agentSystemdEnvPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(agentSystemdEnvPath), 0o755); err != nil {
		return err
	}
	content := strings.Join([]string{
		"# Optional overrides for client/client.sh",
		"# WEB=127.0.0.1:7003",
		"# CONFIG=agent.json",
		"# SERVER=",
		"# TOKEN=",
		"",
	}, "\n")
	return os.WriteFile(agentSystemdEnvPath, []byte(content), 0o644)
}

func syncInstalledAgentSystemdUnit(moduleDir string) error {
	if strings.TrimSpace(moduleDir) == "" {
		return fmt.Errorf("module dir is required")
	}
	if err := ensureAgentSystemdEnvFile(); err != nil {
		return err
	}
	want := agentSystemdUnitContent(moduleDir)
	have, err := os.ReadFile(agentSystemdUnitPath)
	if err == nil && string(have) == want {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.WriteFile(agentSystemdUnitPath, []byte(want), 0o644); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "daemon-reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("systemctl daemon-reload failed: %s", msg)
	}
	return nil
}
