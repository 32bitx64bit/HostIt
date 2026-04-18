package updater

import (
	"sync"

	"hostit/shared/configio"
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
	if _, err := configio.Load(s.Path, &st); err != nil {
		return persistedState{}, err
	}
	return st, nil
}

func (s *Store) Save(st persistedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return configio.Save(s.Path, st)
}
