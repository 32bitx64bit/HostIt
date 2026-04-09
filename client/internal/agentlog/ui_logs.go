package agentlog

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"hostit/shared/logging"
)

type UILogEntry struct {
	TimeUnix int64  `json:"timeUnix"`
	Level    string `json:"level"`
	Source   string `json:"source"`
	Message  string `json:"message"`
}

type UILogBuffer struct {
	mu      sync.RWMutex
	entries []UILogEntry
	maxSize int
}

func NewUILogBuffer(maxSize int) *UILogBuffer {
	if maxSize <= 0 {
		maxSize = 1000
	}
	return &UILogBuffer{entries: make([]UILogEntry, 0, maxSize), maxSize: maxSize}
}

func (b *UILogBuffer) Add(entry UILogEntry) {
	if b == nil {
		return
	}
	entry.Level = strings.ToUpper(strings.TrimSpace(entry.Level))
	if entry.Level == "" {
		entry.Level = "INFO"
	}
	entry.Source = strings.TrimSpace(entry.Source)
	if entry.Source == "" {
		entry.Source = "agent"
	}
	entry.Message = strings.TrimSpace(entry.Message)
	if entry.Message == "" {
		return
	}
	if entry.TimeUnix == 0 {
		entry.TimeUnix = time.Now().Unix()
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, entry)
	if len(b.entries) > b.maxSize {
		copy(b.entries, b.entries[len(b.entries)-b.maxSize:])
		b.entries = b.entries[:b.maxSize]
	}
}

func (b *UILogBuffer) Entries(filter string, limit int) []UILogEntry {
	if b == nil {
		return nil
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make([]UILogEntry, 0, limit)
	for i := len(b.entries) - 1; i >= 0 && len(out) < limit; i-- {
		entry := b.entries[i]
		if !matchesUILogFilter(entry.Level, filter) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func (b *UILogBuffer) Stats() map[string]int {
	stats := map[string]int{"all": 0, "warning": 0, "error": 0}
	if b == nil {
		return stats
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	stats["all"] = len(b.entries)
	for _, entry := range b.entries {
		if matchesUILogFilter(entry.Level, "warning") {
			stats["warning"]++
		}
		if matchesUILogFilter(entry.Level, "error") {
			stats["error"]++
		}
	}
	return stats
}

type uiLogWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	source string
	target *UILogBuffer
}

func NewUILogWriter(source string, target *UILogBuffer) io.Writer {
	if target == nil {
		return io.Discard
	}
	return &uiLogWriter{source: strings.TrimSpace(source), target: target}
}

func (w *uiLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.buf.Write(p); err != nil {
		return 0, err
	}
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}
		w.target.Add(UILogEntry{
			TimeUnix: time.Now().Unix(),
			Level:    detectUILogLevel(line),
			Source:   w.source,
			Message:  trimStdLogPrefix(line),
		})
	}
	return len(p), nil
}

func AddStructuredEntry(entry logging.Entry) {
	if UILogs == nil {
		return
	}
	msg := strings.TrimSpace(entry.Message)
	if len(entry.Fields) > 0 {
		keys := make([]string, 0, len(entry.Fields))
		for k := range entry.Fields {
			if k == "category" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, entry.Fields[k]))
		}
		if len(parts) > 0 {
			msg += " " + strings.Join(parts, " ")
		}
	}
	source := strings.TrimSpace(string(entry.Category))
	if source == "" {
		source = strings.TrimSpace(entry.Component)
	}
	UILogs.Add(UILogEntry{TimeUnix: entry.Time.Unix(), Level: entry.LevelStr, Source: source, Message: msg})
}

func trimStdLogPrefix(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 20 {
		if _, err := time.Parse("2006/01/02 15:04:05", s[:19]); err == nil {
			return strings.TrimSpace(s[20:])
		}
	}
	return s
}

func detectUILogLevel(s string) string {
	upper := strings.ToUpper(strings.TrimSpace(s))
	switch {
	case strings.Contains(upper, "FATAL"):
		return "FATAL"
	case strings.Contains(upper, "ERROR") || strings.Contains(strings.ToLower(s), "error handling"):
		return "ERROR"
	case strings.Contains(upper, "WARN") || strings.Contains(upper, "WARNING"):
		return "WARN"
	case strings.Contains(upper, "DEBUG"):
		return "DEBUG"
	case strings.Contains(upper, "TRACE"):
		return "TRACE"
	default:
		return "INFO"
	}
}

func matchesUILogFilter(level string, filter string) bool {
	level = strings.ToUpper(strings.TrimSpace(level))
	switch strings.ToLower(strings.TrimSpace(filter)) {
	case "", "all":
		return true
	case "warning", "warn", "warnings":
		return level == "WARN" || level == "ERROR" || level == "FATAL"
	case "error", "errors":
		return level == "ERROR" || level == "FATAL"
	default:
		return true
	}
}
