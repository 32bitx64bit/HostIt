package updater

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type persistedState struct {
	LastCheckUnix    int64     `json:"lastCheckUnix"`
	AvailableVersion string    `json:"availableVersion"`
	AvailableURL     string    `json:"availableURL"`
	SkipVersion      string    `json:"skipVersion"`
	RemindUntilUnix  int64     `json:"remindUntilUnix"`
	Job              JobStatus `json:"job"`
}

type Store struct {
	Path string
	mu   sync.Mutex
}

func (s *Store) Load() (persistedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var st persistedState
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	if len(b) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return persistedState{}, err
	}
	return st, nil
}

func (s *Store) Save(st persistedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Path == "" {
		return errors.New("empty store path")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
