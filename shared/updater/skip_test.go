package updater

import (
	"path/filepath"
	"testing"
)

func TestSkipAndRemindSuppressPopup(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "update_state_client.json")
	m := NewManager("irrelevant/repo", ComponentClient, "client.zip", t.TempDir(), storePath)

	// Simulate a successful check that found a newer version than the current build.
	m.mu.Lock()
	m.st.AvailableVersion = "9.9.9"
	m.st.Job.State = JobIdle
	m.mu.Unlock()

	st := m.Status()
	if !st.UpdateAvailable {
		t.Fatalf("expected updateAvailable=true, got status %+v", st)
	}
	if !st.ShowPopup {
		t.Fatalf("expected ShowPopup=true before skip, got suppressed=%v", st.Suppressed)
	}

	// Skip the available version.
	if err := m.SkipAvailableVersion(); err != nil {
		t.Fatal(err)
	}
	st = m.Status()
	if !st.Suppressed || st.ShowPopup {
		t.Fatalf("after skip: suppressed=%v showPopup=%v, want suppressed=true showPopup=false", st.Suppressed, st.ShowPopup)
	}

	// A new version should un-suppress (skip only applies to the skipped version).
	m.mu.Lock()
	m.st.AvailableVersion = "9.9.10"
	m.mu.Unlock()
	st = m.Status()
	if st.Suppressed || !st.ShowPopup {
		t.Fatalf("after new version: suppressed=%v showPopup=%v, want suppressed=false showPopup=true", st.Suppressed, st.ShowPopup)
	}

	// Remind-later should suppress until the deadline.
	if err := m.RemindLater(60 * 1e9); err != nil { // 60s
		t.Fatal(err)
	}
	st = m.Status()
	if !st.Suppressed || st.ShowPopup {
		t.Fatalf("after remind: suppressed=%v showPopup=%v, want suppressed=true showPopup=false", st.Suppressed, st.ShowPopup)
	}

	// State must round-trip across restart (re-load the store).
	m2 := NewManager("irrelevant/repo", ComponentClient, "client.zip", t.TempDir(), storePath)
	st = m2.Status()
	if !st.Suppressed {
		t.Fatalf("skip/remind not persisted across reload: suppressed=%v", st.Suppressed)
	}
}

func TestNewManagerClearsStaleRunningAndRestartingJob(t *testing.T) {
	cases := []struct {
		name  string
		state JobState
		restr bool
	}{
		{"stale running", JobRunning, false},
		{"lingering restarting", JobSuccess, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storePath := filepath.Join(t.TempDir(), "state.json")
			seed := NewManager("r/repo", ComponentClient, "a.zip", t.TempDir(), storePath)
			seed.mu.Lock()
			seed.st.Job = JobStatus{State: tc.state, Restarting: tc.restr, TargetVersion: "9.9.9"}
			seed.mu.Unlock()
			if err := seed.Store.Save(seed.st); err != nil {
				t.Fatal(err)
			}

			m := NewManager("r/repo", ComponentClient, "a.zip", t.TempDir(), storePath)
			if got := m.Status().Job.State; got != JobIdle {
				t.Fatalf("job state after reload = %q, want %q", got, JobIdle)
			}
		})
	}
}
