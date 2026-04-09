package agentlog

import (
	"os"

	"hostit/shared/logging"
)

var (
	Log *logging.Logger

	Dashboard *logging.DashboardHook
	UILogs    *UILogBuffer
)

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

	Dashboard = logging.NewDashboardHook(500, logging.LevelInfo)
	UILogs = NewUILogBuffer(2000)
	Log.AddHook(Dashboard.Hook())
	Log.AddHook(AddStructuredEntry)

	logging.SetGlobal(Log)
}

func SetLevel(level logging.Level) {
	if Log != nil {
		Log.SetLevel(level)
	}
}

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

func SetTrace(enabled bool) {
	if Log == nil {
		return
	}
	if enabled {
		Log.SetLevel(logging.LevelTrace)
	}
}

func System() *logging.Logger {
	return Log.WithCategory(logging.CatSystem)
}

func Control() *logging.Logger {
	return Log.WithCategory(logging.CatControl)
}

func Data() *logging.Logger {
	return Log.WithCategory(logging.CatData)
}

func UDP() *logging.Logger {
	return Log.WithCategory(logging.CatUDP)
}

func TCP() *logging.Logger {
	return Log.WithCategory(logging.CatTCP)
}

func Pool() *logging.Logger {
	return Log.WithCategory(logging.CatPool)
}

func Pairing() *logging.Logger {
	return Log.WithCategory(logging.CatPairing)
}

func Health() *logging.Logger {
	return Log.WithCategory(logging.CatHealth)
}

func Encryption() *logging.Logger {
	return Log.WithCategory(logging.CatEncryption)
}

func F(keyvals ...any) map[string]any {
	return logging.F(keyvals...)
}
