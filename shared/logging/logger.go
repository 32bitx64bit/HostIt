// Package logging provides a centralized, structured logging system for HostIt.
// It supports multiple output destinations including console, dashboard events,
// and custom hooks for extensibility.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level represents the severity of a log message.
type Level int

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

func (l Level) String() string {
	switch l {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a string into a Level.
func ParseLevel(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "TRACE":
		return LevelTrace
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR":
		return LevelError
	case "FATAL":
		return LevelFatal
	default:
		return LevelInfo
	}
}

// Category represents a functional area of the system for filtering.
type Category string

const (
	CatSystem     Category = "system"
	CatControl    Category = "control"
	CatData       Category = "data"
	CatUDP        Category = "udp"
	CatTCP        Category = "tcp"
	CatPool       Category = "pool"
	CatPairing    Category = "pairing"
	CatAuth       Category = "auth"
	CatDashboard  Category = "dashboard"
	CatHealth     Category = "health"
	CatEncryption Category = "encryption"
)

// Entry represents a single log entry.
type Entry struct {
	Time      time.Time      `json:"time"`
	Level     Level          `json:"level"`
	LevelStr  string         `json:"level_str"`
	Category  Category       `json:"category"`
	Component string         `json:"component"` // "server" or "agent"
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
	Error     error          `json:"-"`
	ErrorStr  string         `json:"error,omitempty"`
	Caller    string         `json:"caller,omitempty"`
}

// Hook is called for each log entry. Hooks can be used to send logs to dashboards,
// external services, etc.
type Hook func(entry Entry)

// Logger is the main logging interface.
type Logger struct {
	mu         sync.RWMutex
	level      atomic.Int32
	output     io.Writer
	component  string
	hooks      []Hook
	fields     map[string]any
	jsonFormat bool
	showCaller bool

	// Rate limiting for high-volume logs
	rateLimiter *rateLimiter
}

// Config holds logger configuration.
type Config struct {
	Level      Level
	Output     io.Writer
	Component  string // "server" or "agent"
	JSONFormat bool
	ShowCaller bool
	RateLimit  time.Duration // Minimum interval between same-message logs
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig(component string) Config {
	return Config{
		Level:      LevelInfo,
		Output:     os.Stderr,
		Component:  component,
		JSONFormat: false,
		ShowCaller: false,
		RateLimit:  100 * time.Millisecond,
	}
}

// New creates a new Logger with the given configuration.
func New(cfg Config) *Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stderr
	}
	l := &Logger{
		output:      cfg.Output,
		component:   cfg.Component,
		hooks:       make([]Hook, 0),
		fields:      make(map[string]any),
		jsonFormat:  cfg.JSONFormat,
		showCaller:  cfg.ShowCaller,
		rateLimiter: newRateLimiter(cfg.RateLimit),
	}
	l.level.Store(int32(cfg.Level))
	return l
}

// Global logger instance
var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

// Global returns the global logger instance, initializing it if necessary.
func Global() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = New(DefaultConfig("app"))
	})
	return globalLogger
}

// SetGlobal sets the global logger instance.
func SetGlobal(l *Logger) {
	globalLoggerOnce.Do(func() {}) // Ensure once is triggered
	globalLogger = l
}

// SetLevel sets the minimum log level.
func (l *Logger) SetLevel(level Level) {
	l.level.Store(int32(level))
}

// GetLevel returns the current minimum log level.
func (l *Logger) GetLevel() Level {
	return Level(l.level.Load())
}

// SetLevelFromEnv sets the level from environment variables.
// Checks HOSTIT_LOG_LEVEL and PLAYIT_LOG_LEVEL.
func (l *Logger) SetLevelFromEnv() {
	v := strings.TrimSpace(os.Getenv("HOSTIT_LOG_LEVEL"))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("PLAYIT_LOG_LEVEL"))
	}
	if v != "" {
		l.SetLevel(ParseLevel(v))
	}
}

// AddHook adds a hook that will be called for each log entry.
func (l *Logger) AddHook(hook Hook) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hooks = append(l.hooks, hook)
}

// WithFields returns a new logger with additional fields.
func (l *Logger) WithFields(fields map[string]any) *Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	newFields := make(map[string]any, len(l.fields)+len(fields))
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}

	return &Logger{
		output:      l.output,
		component:   l.component,
		hooks:       l.hooks,
		fields:      newFields,
		jsonFormat:  l.jsonFormat,
		showCaller:  l.showCaller,
		rateLimiter: l.rateLimiter,
	}
}

// WithField returns a new logger with an additional field.
func (l *Logger) WithField(key string, value any) *Logger {
	return l.WithFields(map[string]any{key: value})
}

// WithError returns a new logger with the error field set.
func (l *Logger) WithError(err error) *Logger {
	return l.WithField("error", err)
}

// WithCategory returns a new logger with the category field set.
func (l *Logger) WithCategory(cat Category) *Logger {
	return l.WithField("category", string(cat))
}

func (l *Logger) log(level Level, cat Category, msg string, fields map[string]any) {
	if level < Level(l.level.Load()) {
		return
	}

	entry := Entry{
		Time:      time.Now(),
		Level:     level,
		LevelStr:  level.String(),
		Category:  cat,
		Component: l.component,
		Message:   msg,
	}

	// Copy logger fields
	l.mu.RLock()
	loggerFields := l.fields
	hooks := l.hooks
	l.mu.RUnlock()

	// Only allocate Fields map when there are actual fields to merge.
	if len(loggerFields) > 0 || len(fields) > 0 {
		entry.Fields = make(map[string]any, len(loggerFields)+len(fields))
		for k, v := range loggerFields {
			entry.Fields[k] = v
		}
		for k, v := range fields {
			if k == "error" {
				if err, ok := v.(error); ok {
					entry.Error = err
					entry.ErrorStr = err.Error()
					continue
				}
			}
			entry.Fields[k] = v
		}
	}

	// Add caller info if enabled
	if l.showCaller {
		if _, file, line, ok := runtime.Caller(3); ok {
			// Shorten the file path
			if idx := strings.LastIndex(file, "/"); idx >= 0 {
				file = file[idx+1:]
			}
			entry.Caller = fmt.Sprintf("%s:%d", file, line)
		}
	}

	// Format and write
	l.write(entry)

	// Call hooks
	for _, hook := range hooks {
		hook(entry)
	}
}

func (l *Logger) write(entry Entry) {
	var output string
	if l.jsonFormat {
		data, _ := json.Marshal(entry)
		output = string(data) + "\n"
	} else {
		output = l.formatText(entry)
	}

	l.mu.Lock()
	_, _ = io.WriteString(l.output, output)
	l.mu.Unlock()
}

func (l *Logger) formatText(entry Entry) string {
	var b strings.Builder

	// Timestamp
	b.WriteString(entry.Time.Format("2006/01/02 15:04:05"))
	b.WriteString(" ")

	// Level with padding
	b.WriteString(fmt.Sprintf("%-5s", entry.LevelStr))
	b.WriteString(" ")

	// Category
	if entry.Category != "" {
		b.WriteString("[")
		b.WriteString(string(entry.Category))
		b.WriteString("] ")
	}

	// Message
	b.WriteString(entry.Message)

	// Fields
	if len(entry.Fields) > 0 {
		for k, v := range entry.Fields {
			if k == "category" {
				continue // Already shown
			}
			b.WriteString(fmt.Sprintf(" %s=%v", k, v))
		}
	}

	// Error
	if entry.ErrorStr != "" {
		b.WriteString(" error=\"")
		b.WriteString(entry.ErrorStr)
		b.WriteString("\"")
	}

	// Caller
	if entry.Caller != "" {
		b.WriteString(" caller=")
		b.WriteString(entry.Caller)
	}

	b.WriteString("\n")
	return b.String()
}

// Category-specific logging methods

func (l *Logger) Trace(cat Category, msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log(LevelTrace, cat, msg, f)
}

func (l *Logger) Debug(cat Category, msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log(LevelDebug, cat, msg, f)
}

func (l *Logger) Info(cat Category, msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log(LevelInfo, cat, msg, f)
}

func (l *Logger) Warn(cat Category, msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log(LevelWarn, cat, msg, f)
}

func (l *Logger) Error(cat Category, msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log(LevelError, cat, msg, f)
}

func (l *Logger) Fatal(cat Category, msg string, fields ...map[string]any) {
	f := mergeFields(fields)
	l.log(LevelFatal, cat, msg, f)
	os.Exit(1)
}

// Convenience methods with formatted messages

func (l *Logger) Tracef(cat Category, format string, args ...any) {
	if LevelTrace < Level(l.level.Load()) {
		return
	}
	l.Trace(cat, fmt.Sprintf(format, args...))
}

func (l *Logger) Debugf(cat Category, format string, args ...any) {
	if LevelDebug < Level(l.level.Load()) {
		return
	}
	l.Debug(cat, fmt.Sprintf(format, args...))
}

func (l *Logger) Infof(cat Category, format string, args ...any) {
	if LevelInfo < Level(l.level.Load()) {
		return
	}
	l.Info(cat, fmt.Sprintf(format, args...))
}

func (l *Logger) Warnf(cat Category, format string, args ...any) {
	if LevelWarn < Level(l.level.Load()) {
		return
	}
	l.Warn(cat, fmt.Sprintf(format, args...))
}

func (l *Logger) Errorf(cat Category, format string, args ...any) {
	if LevelError < Level(l.level.Load()) {
		return
	}
	l.Error(cat, fmt.Sprintf(format, args...))
}

func mergeFields(fields []map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	result := make(map[string]any)
	for _, f := range fields {
		for k, v := range f {
			result[k] = v
		}
	}
	return result
}

// F is a shortcut for creating field maps.
func F(keyvals ...any) map[string]any {
	if len(keyvals) == 0 {
		return nil
	}
	m := make(map[string]any, len(keyvals)/2)
	for i := 0; i < len(keyvals)-1; i += 2 {
		if key, ok := keyvals[i].(string); ok {
			m[key] = keyvals[i+1]
		}
	}
	return m
}
