// Package agentlog provides centralized logging setup for the HostIt agent.
package agentlog

import (
	"os"

	"hostit/shared/logging"
)

var (
	// Log is the global agent logger instance.
	Log *logging.Logger

	// Dashboard is the dashboard hook for collecting events.
	Dashboard *logging.DashboardHook
)

// Init initializes the agent logging system.
func Init() {
	cfg := logging.Config{
		Level:      logging.LevelInfo,
		Output:     os.Stderr,
		Component:  "agent",
		JSONFormat: false,
		ShowCaller: false,
		RateLimit:  100 * 1e6, // 100ms in nanoseconds
	}

	Log = logging.New(cfg)
	Log.SetLevelFromEnv()

	// Create dashboard hook to collect events for web UI
	Dashboard = logging.NewDashboardHook(500, logging.LevelInfo)
	Log.AddHook(Dashboard.Hook())

	logging.SetGlobal(Log)
}

// SetLevel changes the log level.
func SetLevel(level logging.Level) {
	if Log != nil {
		Log.SetLevel(level)
	}
}

// SetDebug enables debug level logging.
func SetDebug(enabled bool) {
	if Log == nil {
		return
	}
	if enabled {
		Log.SetLevel(logging.LevelDebug)
	} else {
		Log.SetLevel(logging.LevelInfo)
	}
}

// SetTrace enables trace level logging.
func SetTrace(enabled bool) {
	if Log == nil {
		return
	}
	if enabled {
		Log.SetLevel(logging.LevelTrace)
	}
}

// Common field helpers for consistent logging.

// System returns a logger for system-level events.
func System() *logging.Logger {
	return Log.WithCategory(logging.CatSystem)
}

// Control returns a logger for control channel events.
func Control() *logging.Logger {
	return Log.WithCategory(logging.CatControl)
}

// Data returns a logger for data channel events.
func Data() *logging.Logger {
	return Log.WithCategory(logging.CatData)
}

// UDP returns a logger for UDP events.
func UDP() *logging.Logger {
	return Log.WithCategory(logging.CatUDP)
}

// TCP returns a logger for TCP events.
func TCP() *logging.Logger {
	return Log.WithCategory(logging.CatTCP)
}

// Pool returns a logger for connection pool events.
func Pool() *logging.Logger {
	return Log.WithCategory(logging.CatPool)
}

// Pairing returns a logger for connection pairing events.
func Pairing() *logging.Logger {
	return Log.WithCategory(logging.CatPairing)
}

// Health returns a logger for health check events.
func Health() *logging.Logger {
	return Log.WithCategory(logging.CatHealth)
}

// Encryption returns a logger for encryption-related events.
func Encryption() *logging.Logger {
	return Log.WithCategory(logging.CatEncryption)
}

// F is a shortcut for creating field maps.
func F(keyvals ...any) map[string]any {
	return logging.F(keyvals...)
}
