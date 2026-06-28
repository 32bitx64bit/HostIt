package updater

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyUpdatePreservesMailDirectory(t *testing.T) {
	moduleDir := t.TempDir()

	// Simulate an existing deployment with mail data on disk.
	mailDir := filepath.Join(moduleDir, "mail")
	if err := os.MkdirAll(mailDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mailDB := filepath.Join(mailDir, "mail.db")
	want := []byte("MAIL-DATA-MUST-SURVIVE")
	if err := os.WriteFile(mailDB, want, 0o600); err != nil {
		t.Fatal(err)
	}

	// A stale file that is NOT preserved and NOT in the update zip: it must be removed,
	// proving syncDir actually ran and the mail dir survived because of PreservePaths.
	stalePath := filepath.Join(moduleDir, "leftover.txt")
	if err := os.WriteFile(stalePath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	zipPath := writeTestComponentZip(t, "client")

	err := ApplyZipFileUpdate(context.Background(), zipPath, ApplyOptions{
		ModuleDir:      moduleDir,
		ExpectedFolder: "client",
		PreservePaths:  []string{mailDir},
	}, os.Stderr)
	if err != nil {
		t.Fatalf("ApplyZipFileUpdate() error = %v", err)
	}

	got, err := os.ReadFile(mailDB)
	if err != nil {
		t.Fatalf("mail.db missing after update: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("mail.db contents changed after update: got %q, want %q", got, want)
	}

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("stale file %q should have been removed by update (err=%v)", stalePath, err)
	}
}
