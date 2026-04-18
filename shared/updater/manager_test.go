package updater

import (
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func writeTestComponentZip(t *testing.T, component string) string {
	t.Helper()

	zipPath := filepath.Join(t.TempDir(), component+".zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	header := &zip.FileHeader{Name: component + "/build.sh", Method: zip.Deflate}
	header.SetMode(0o755)
	w, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("#!/bin/sh\nexit 0\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	return zipPath
}

func waitForJob(t *testing.T, m *Manager) JobStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := m.Status().Job
		if st.State != JobRunning {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for updater job to finish")
	return JobStatus{}
}

func TestApplyLocalDetachesRequestContext(t *testing.T) {
	moduleDir := t.TempDir()
	storePath := filepath.Join(t.TempDir(), "updater-state.json")
	zipPath := writeTestComponentZip(t, "server")

	prevExec := execCommandContext
	defer func() { execCommandContext = prevExec }()

	var sawCanceled atomic.Bool
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if ctx.Err() != nil {
			sawCanceled.Store(true)
		}
		return exec.Command("sh", "-c", "exit 0")
	}

	m := NewManager("", ComponentServer, "", moduleDir, storePath)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started, err := m.ApplyLocal(ctx, zipPath, "")
	if err != nil {
		t.Fatalf("ApplyLocal() error = %v", err)
	}
	if !started {
		t.Fatal("ApplyLocal() started = false, want true")
	}

	job := waitForJob(t, m)
	if job.State != JobSuccess {
		t.Fatalf("job state = %q, want %q; last_error=%q log=%q", job.State, JobSuccess, job.LastError, job.Log)
	}
	if sawCanceled.Load() {
		t.Fatal("build command received a canceled context")
	}
}
