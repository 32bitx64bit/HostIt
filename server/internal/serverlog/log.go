package serverlog

import (
	"os"

	"hostit/shared/logging"
)

var (
	Log *logging.Logger
)

func Init() {
	Log = logging.NewLogger(logging.DefaultSystemCap, logging.DefaultRouteCap, logging.DefaultEventCap)
	Log.SetOutput(os.Stderr)
	Log.SetLevel(logging.LevelInfo)
	Log.SetLevelFromEnv()
	logging.SetGlobal(Log)
}

func SetLevel(level logging.Level) {
	if Log != nil {
		Log.SetLevel(level)
	}
}

func GetLevel() logging.Level {
	if Log != nil {
		return Log.GetLevel()
	}
	return logging.LevelInfo
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

func AddHook(hook func(logging.LogEntry)) {
	if Log != nil {
		Log.AddHook(hook)
	}
}

func F(keyvals ...any) map[string]any {
	return logging.F(keyvals...)
}
