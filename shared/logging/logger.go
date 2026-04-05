package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
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

type LogEntry struct {
	Timestamp int64             `json:"ts"`
	Level     string            `json:"level"`
	Route     string            `json:"route"`
	Category  string            `json:"cat"`
	Message   string            `json:"msg"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type LogBuffer struct {
	mu       sync.RWMutex
	entries  []LogEntry
	capacity int
	head     int
	size     int
}

func NewLogBuffer(capacity int) *LogBuffer {
	return &LogBuffer{
		entries:  make([]LogEntry, capacity),
		capacity: capacity,
	}
}

func (b *LogBuffer) Add(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[b.head] = entry
	b.head = (b.head + 1) % b.capacity
	if b.size < b.capacity {
		b.size++
	}
}

func (b *LogBuffer) GetAll() []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.size == 0 {
		return nil
	}
	result := make([]LogEntry, b.size)
	if b.head >= b.size {
		copy(result, b.entries[b.head-b.size:b.head])
	} else {
		start := b.capacity - (b.size - b.head)
		copy(result, b.entries[start:b.capacity])
		copy(result[b.capacity-start:], b.entries[:b.head])
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp < result[j].Timestamp
	})
	return result
}

func (b *LogBuffer) GetSince(timestamp int64) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.size == 0 {
		return nil
	}
	all := b.GetAll()
	result := make([]LogEntry, 0)
	for _, e := range all {
		if e.Timestamp > timestamp {
			result = append(result, e)
		}
	}
	return result
}

func (b *LogBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = make([]LogEntry, b.capacity)
	b.head = 0
	b.size = 0
}

type Logger struct {
	mu        sync.RWMutex
	systemBuf *LogBuffer
	routeBufs map[string]*LogBuffer
	eventBufs map[string]*LogBuffer
	output    io.Writer
	minLevel  Level
	systemCap int
	routeCap  int
	eventCap  int
	component string
	hooks     []func(LogEntry)
}

const (
	DefaultSystemCap = 1000
	DefaultRouteCap  = 500
	DefaultEventCap  = 200
)

var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

func Global() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = NewLogger(DefaultSystemCap, DefaultRouteCap, DefaultEventCap)
	})
	return globalLogger
}

func SetGlobal(l *Logger) {
	globalLoggerOnce.Do(func() {})
	globalLogger = l
}

func NewLogger(systemCap, routeCap, eventCap int) *Logger {
	return &Logger{
		systemBuf: NewLogBuffer(systemCap),
		routeBufs: make(map[string]*LogBuffer),
		eventBufs: make(map[string]*LogBuffer),
		output:    os.Stderr,
		minLevel:  LevelInfo,
		systemCap: systemCap,
		routeCap:  routeCap,
		eventCap:  eventCap,
	}
}

func New(cfg Config) *Logger {
	l := NewLogger(DefaultSystemCap, DefaultRouteCap, DefaultEventCap)
	if cfg.Output != nil {
		l.output = cfg.Output
	}
	if cfg.Level >= LevelDebug && cfg.Level <= LevelError {
		l.minLevel = cfg.Level
	}
	l.component = cfg.Component
	return l
}

type Config struct {
	Level      Level
	Output     io.Writer
	Component  string
	JSONFormat bool
	ShowCaller bool
}

func DefaultConfig(component string) Config {
	return Config{
		Level:      LevelInfo,
		Output:     os.Stderr,
		Component:  component,
		JSONFormat: false,
		ShowCaller: false,
	}
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.minLevel = level
	l.mu.Unlock()
}

func (l *Logger) GetLevel() Level {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.minLevel
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

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	l.output = w
	l.mu.Unlock()
}

func (l *Logger) getRouteBuffer(route string) *LogBuffer {
	l.mu.Lock()
	defer l.mu.Unlock()
	buf, ok := l.routeBufs[route]
	if !ok {
		buf = NewLogBuffer(l.routeCap)
		l.routeBufs[route] = buf
	}
	return buf
}

func (l *Logger) getEventBuffer(route string) *LogBuffer {
	l.mu.Lock()
	defer l.mu.Unlock()
	buf, ok := l.eventBufs[route]
	if !ok {
		buf = NewLogBuffer(l.eventCap)
		l.eventBufs[route] = buf
	}
	return buf
}

func (l *Logger) addEntry(level Level, route string, category Category, msg string, fields map[string]string) {
	l.mu.RLock()
	minLevel := l.minLevel
	output := l.output
	l.mu.RUnlock()

	if level < minLevel {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UnixMilli(),
		Level:     level.String(),
		Route:     route,
		Category:  string(category),
		Message:   msg,
		Fields:    fields,
	}

	if route == "" {
		l.systemBuf.Add(entry)
	} else {
		l.getRouteBuffer(route).Add(entry)
	}

	if level == LevelError || level == LevelWarn {
		l.getEventBuffer(route).Add(entry)
	}

	if output != nil {
		data, _ := json.Marshal(entry)
		output.Write(append(data, '\n'))
	}

	l.runHooks(entry)
}

func (l *Logger) logf(level Level, cat Category, format string, args ...any) {
	l.addEntry(level, "", cat, fmt.Sprintf(format, args...), nil)
}

func (l *Logger) log(level Level, cat Category, msg string, fields map[string]any) {
	strFields := make(map[string]string)
	for k, v := range fields {
		strFields[k] = fmt.Sprintf("%v", v)
	}
	l.addEntry(level, "", cat, msg, strFields)
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
	l.log(LevelError, cat, msg, f)
	os.Exit(1)
}

func (l *Logger) Debugf(cat Category, format string, args ...any) {
	if LevelDebug < l.minLevel {
		return
	}
	l.logf(LevelDebug, cat, format, args...)
}

func (l *Logger) Infof(cat Category, format string, args ...any) {
	if LevelInfo < l.minLevel {
		return
	}
	l.logf(LevelInfo, cat, format, args...)
}

func (l *Logger) Warnf(cat Category, format string, args ...any) {
	if LevelWarn < l.minLevel {
		return
	}
	l.logf(LevelWarn, cat, format, args...)
}

func (l *Logger) Errorf(cat Category, format string, args ...any) {
	if LevelError < l.minLevel {
		return
	}
	l.logf(LevelError, cat, format, args...)
}

func (l *Logger) WithField(key string, value any) *Logger {
	return l
}

func (l *Logger) WithFields(fields map[string]any) *Logger {
	return l
}

func (l *Logger) WithCategory(cat Category) *Logger {
	return l
}

func (l *Logger) WithError(err error) *Logger {
	return l
}

func (l *Logger) AddHook(hook func(LogEntry)) {
	l.mu.Lock()
	l.hooks = append(l.hooks, hook)
	l.mu.Unlock()
}

func (l *Logger) runHooks(entry LogEntry) {
	l.mu.RLock()
	hooks := l.hooks
	l.mu.RUnlock()
	for _, h := range hooks {
		if h != nil {
			h(entry)
		}
	}
}

func (l *Logger) RouteLog(level Level, route string, category Category, msg string, fields map[string]string) {
	l.addEntry(level, route, category, msg, fields)
}

func (l *Logger) RouteInfo(route string, category Category, msg string, fields map[string]string) {
	l.addEntry(LevelInfo, route, category, msg, fields)
}

func (l *Logger) RouteWarn(route string, category Category, msg string, fields map[string]string) {
	l.addEntry(LevelWarn, route, category, msg, fields)
}

func (l *Logger) RouteError(route string, category Category, msg string, fields map[string]string) {
	l.addEntry(LevelError, route, category, msg, fields)
}

func (l *Logger) RouteDebug(route string, category Category, msg string, fields map[string]string) {
	l.addEntry(LevelDebug, route, category, msg, fields)
}

func (l *Logger) GetLogs(route string) []LogEntry {
	if route == "" {
		return l.systemBuf.GetAll()
	}
	l.mu.RLock()
	buf, ok := l.routeBufs[route]
	l.mu.RUnlock()
	if !ok {
		return nil
	}
	return buf.GetAll()
}

func (l *Logger) GetSystemLogs() []LogEntry {
	return l.systemBuf.GetAll()
}

func (l *Logger) GetAllLogs() []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]LogEntry, 0)
	result = append(result, l.systemBuf.GetAll()...)

	for _, buf := range l.routeBufs {
		result = append(result, buf.GetAll()...)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp < result[j].Timestamp
	})
	return result
}

func (l *Logger) GetEvents(route string) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if route == "" {
		result := make([]LogEntry, 0)
		for _, buf := range l.eventBufs {
			result = append(result, buf.GetAll()...)
		}
		sort.Slice(result, func(i, j int) bool {
			return result[i].Timestamp < result[j].Timestamp
		})
		return result
	}

	buf, ok := l.eventBufs[route]
	if !ok {
		return nil
	}
	return buf.GetAll()
}

func (l *Logger) GetRouteNames() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	names := make([]string, 0, len(l.routeBufs))
	for name := range l.routeBufs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (l *Logger) ClearAll() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.systemBuf.Clear()
	l.routeBufs = make(map[string]*LogBuffer)
	l.eventBufs = make(map[string]*LogBuffer)
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
