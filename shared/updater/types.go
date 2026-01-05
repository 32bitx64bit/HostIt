package updater

import "time"

type Component string

const (
	ComponentServer Component = "server"
	ComponentClient Component = "client"
)

type JobState string

const (
	JobIdle    JobState = "idle"
	JobRunning JobState = "running"
	JobSuccess JobState = "success"
	JobFailed  JobState = "failed"
)

type JobStatus struct {
	State         JobState  `json:"state"`
	TargetVersion string    `json:"targetVersion"`
	StartedAtUnix int64     `json:"startedAtUnix"`
	EndedAtUnix   int64     `json:"endedAtUnix"`
	Log           string    `json:"log"`
	LastError     string    `json:"lastError"`
	Restarting    bool      `json:"restarting"`
	UpdatedAt     time.Time `json:"-"`
}

type Status struct {
	CurrentVersion   string `json:"currentVersion"`
	AvailableVersion string `json:"availableVersion"`
	AvailableURL     string `json:"availableURL"`
	CheckedAtUnix    int64  `json:"checkedAtUnix"`
	RemindUntilUnix  int64  `json:"remindUntilUnix"`
	SkipVersion      string `json:"skipVersion"`

	UpdateAvailable bool `json:"updateAvailable"`
	Suppressed      bool `json:"suppressed"`
	ShowPopup       bool `json:"showPopup"`

	Job JobStatus `json:"job"`
}
