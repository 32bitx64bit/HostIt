package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type systemdStatusResponse struct {
	Available bool   `json:"available"`
	Service   string `json:"service"`
	Active    string `json:"active"`
	Error     string `json:"error,omitempty"`
}

func systemdAction(ctx context.Context, action string, service string) error {
	if !systemctlAvailable() {
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

func systemdStatus(ctx context.Context, service string) systemdStatusResponse {
	resp := systemdStatusResponse{Available: systemctlAvailable(), Service: service}
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
