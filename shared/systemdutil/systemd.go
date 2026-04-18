package systemdutil

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type StatusResponse struct {
	Available bool   `json:"available"`
	Service   string `json:"service"`
	Active    string `json:"active"`
	Error     string `json:"error,omitempty"`
}

func RunningUnderSystemd() bool {
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

func SystemctlAvailable() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

var allowedActions = map[string]bool{
	"start":      true,
	"stop":       true,
	"restart":    true,
	"reload":     true,
	"status":     true,
	"enable":     true,
	"disable":    true,
	"is-active":  true,
	"is-enabled": true,
}

func Action(ctx context.Context, action string, service string) error {
	if !allowedActions[action] {
		return fmt.Errorf("unsupported systemctl action: %s", action)
	}
	if !SystemctlAvailable() {
		return fmt.Errorf("systemctl not found")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", action, service)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("systemctl %s %s: %s", action, service, msg)
	}
	return nil
}

func Status(ctx context.Context, service string) StatusResponse {
	resp := StatusResponse{Available: SystemctlAvailable(), Service: service}
	if !resp.Available {
		resp.Active = "unknown"
		return resp
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", service)
	out, err := cmd.CombinedOutput()
	resp.Active = strings.TrimSpace(string(out))
	if resp.Active == "" {
		resp.Active = "unknown"
	}
	if err != nil {
		resp.Error = strings.TrimSpace(string(out))
		if resp.Error == "" {
			resp.Error = err.Error()
		}
	}
	return resp
}
