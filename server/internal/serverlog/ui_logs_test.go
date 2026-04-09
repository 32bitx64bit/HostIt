package serverlog

import (
	"testing"
	"time"
)

func TestUILogBufferEntriesFilter(t *testing.T) {
	buf := NewUILogBuffer(10)
	buf.Add(UILogEntry{TimeUnix: time.Now().Unix(), Level: "INFO", Source: "test", Message: "info"})
	buf.Add(UILogEntry{TimeUnix: time.Now().Unix(), Level: "WARN", Source: "test", Message: "warn"})
	buf.Add(UILogEntry{TimeUnix: time.Now().Unix(), Level: "ERROR", Source: "test", Message: "error"})

	if got := len(buf.Entries("all", 10)); got != 3 {
		t.Fatalf("Entries(all) len = %d, want 3", got)
	}
	if got := len(buf.Entries("warning", 10)); got != 2 {
		t.Fatalf("Entries(warning) len = %d, want 2", got)
	}
	if got := len(buf.Entries("error", 10)); got != 1 {
		t.Fatalf("Entries(error) len = %d, want 1", got)
	}
}

func TestTrimStdLogPrefix(t *testing.T) {
	got := trimStdLogPrefix("2026/04/09 12:00:00 test message")
	if got != "test message" {
		t.Fatalf("trimStdLogPrefix() = %q, want test message", got)
	}
}
