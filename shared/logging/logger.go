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

type Entry struct {
	Time      time.Time      `json:"time"`
	Level     Level          `json:"level"`
	LevelStr  string         `json:"level_str"`
	Category  Category       `json:"category"`
	Component string         `json:"component"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
	Error     error          `json:"-"`
	ErrorStr  string         `json:"error,omitempty"`
	Caller    string         `json:"caller,omitempty"`
}

type Hook func(entry Entry)

type Logger struct {
	mu         sync.RWMutex
	level      atomic.Int32
	output     io.Writer
	component  string
	hooks      []Hook
	fields     map[string]any
	jsonFormat bool
	showCaller bool

	rateLimiter *rateLimiter
}

type Config struct {
	Level      Level
	Output     io.Writer
	Component  string
	JSONFormat bool
	ShowCaller bool
	RateLimit  time.Duration
}

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

var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

func Global() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = New(DefaultConfig("app"))
	})
	return globalLogger
}

func SetGlobal(l *Logger) {
	globalLoggerOnce.Do(func() {})
	globalLogger = l
}

func (l *Logger) SetLevel(level Level) {
	l.level.Store(int32(level))
}

func (l *Logger) GetLevel() Level {
	return Level(l.level.Load())
}

func (l *Logger) SetLevelFromEnv() {
	v := strings.TrimSpace(os.Getenv("HOSTIT_LOG_LEVEL"))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("PLAYIT_LOG_LEVEL"))
	}
	if v != "" {
		l.SetLevel(ParseLevel(v))
	}
}

func (l *Logger) AddHook(hook Hook) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hooks = append(l.hooks, hook)
}

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

func (l *Logger) WithField(key string, value any) *Logger {
	return l.WithFields(map[string]any{key: value})
}

func (l *Logger) WithError(err error) *Logger {
	return l.WithField("error", err)
}

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

	l.mu.RLock()
	loggerFields := l.fields
	hooks := l.hooks
	l.mu.RUnlock()

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

	if l.showCaller {
		if _, file, line, ok := runtime.Caller(3); ok {
			if idx := strings.LastIndex(file, "/"); idx >= 0 {
				file = file[idx+1:]
			}
			entry.Caller = fmt.Sprintf("%s:%d", file, line)
		}
	}

	l.write(entry)

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

	b.WriteString(entry.Time.Format("2006/01/02 15:04:05"))
	b.WriteString(" ")

	b.WriteString(fmt.Sprintf("%-5s", entry.LevelStr))
	b.WriteString(" ")

	if entry.Category != "" {
		b.WriteString("[")
		b.WriteString(string(entry.Category))
		b.WriteString("] ")
	}

	b.WriteString(entry.Message)

	if len(entry.Fields) > 0 {
		for k, v := range entry.Fields {
			if k == "category" {
				continue
			}
			b.WriteString(fmt.Sprintf(" %s=%v", k, v))
		}
	}

	if entry.ErrorStr != "" {
		b.WriteString(" error=\"")
		b.WriteString(entry.ErrorStr)
		b.WriteString("\"")
	}

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
