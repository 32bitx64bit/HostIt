package udputil

import (
	"sync"
	"time"
)

// SessionStats tracks per-session UDP statistics.
type SessionStats struct {
	mu            sync.RWMutex
	sessions      map[string]*SessionInfo
	globalStats   *Stats
	maxSessions   int
	sessionTTL    time.Duration
}

// SessionInfo holds info about a single UDP session.
type SessionInfo struct {
	ID            string    `json:"id"`
	Route         string    `json:"route"`
	RemoteAddr    string    `json:"remote_addr"`
	LocalTarget   string    `json:"local_target"`
	CreatedAt     time.Time `json:"created_at"`
	LastActivity  time.Time `json:"last_activity"`
	Stats         *Stats    `json:"-"`
	StatsSnapshot StatsSnapshot `json:"stats"`
}

// NewSessionStats creates a session statistics tracker.
func NewSessionStats(maxSessions int, sessionTTL time.Duration) *SessionStats {
	if maxSessions <= 0 {
		maxSessions = 1000
	}
	if sessionTTL <= 0 {
		sessionTTL = 5 * time.Minute
	}
	return &SessionStats{
		sessions:    make(map[string]*SessionInfo),
		globalStats: NewStats(),
		maxSessions: maxSessions,
		sessionTTL:  sessionTTL,
	}
}

// GetOrCreate gets or creates a session.
func (s *SessionStats) GetOrCreate(id, route, remoteAddr, localTarget string) *SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if info, ok := s.sessions[id]; ok {
		info.LastActivity = time.Now()
		return info
	}
	
	// Cleanup old sessions if at capacity
	if len(s.sessions) >= s.maxSessions {
		s.cleanupOldestLocked()
	}
	
	info := &SessionInfo{
		ID:           id,
		Route:        route,
		RemoteAddr:   remoteAddr,
		LocalTarget:  localTarget,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Stats:        NewStats(),
	}
	s.sessions[id] = info
	return info
}

// Get retrieves a session by ID.
func (s *SessionStats) Get(id string) (*SessionInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.sessions[id]
	return info, ok
}

// Remove removes a session.
func (s *SessionStats) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// RecordSend records a send for a session.
func (s *SessionStats) RecordSend(id string, bytes int) {
	s.globalStats.RecordSend(bytes)
	if info, ok := s.Get(id); ok {
		info.Stats.RecordSend(bytes)
		info.LastActivity = time.Now()
	}
}

// RecordReceive records a receive for a session.
func (s *SessionStats) RecordReceive(id string, bytes int) {
	s.globalStats.RecordReceive(bytes)
	if info, ok := s.Get(id); ok {
		info.Stats.RecordReceive(bytes)
		info.LastActivity = time.Now()
	}
}

// GlobalStats returns global statistics.
func (s *SessionStats) GlobalStats() StatsSnapshot {
	return s.globalStats.Snapshot()
}

// SessionCount returns the number of active sessions.
func (s *SessionStats) SessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// ActiveSessions returns info about active sessions.
func (s *SessionStats) ActiveSessions() []SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	result := make([]SessionInfo, 0, len(s.sessions))
	for _, info := range s.sessions {
		infoCopy := *info
		infoCopy.StatsSnapshot = info.Stats.Snapshot()
		result = append(result, infoCopy)
	}
	return result
}

// Cleanup removes expired sessions.
func (s *SessionStats) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	cutoff := time.Now().Add(-s.sessionTTL)
	removed := 0
	for id, info := range s.sessions {
		if info.LastActivity.Before(cutoff) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}

func (s *SessionStats) cleanupOldestLocked() {
	// Remove 10% of sessions, oldest first
	toRemove := s.maxSessions / 10
	if toRemove < 1 {
		toRemove = 1
	}
	
	// Find oldest sessions
	type aged struct {
		id   string
		time time.Time
	}
	var oldest []aged
	for id, info := range s.sessions {
		oldest = append(oldest, aged{id, info.LastActivity})
	}
	
	// Sort by activity time (simple selection for small N)
	for i := 0; i < toRemove && i < len(oldest); i++ {
		minIdx := i
		for j := i + 1; j < len(oldest); j++ {
			if oldest[j].time.Before(oldest[minIdx].time) {
				minIdx = j
			}
		}
		if minIdx != i {
			oldest[i], oldest[minIdx] = oldest[minIdx], oldest[i]
		}
		delete(s.sessions, oldest[i].id)
	}
}

// Summary returns a summary suitable for dashboard display.
type Summary struct {
	ActiveSessions int           `json:"active_sessions"`
	GlobalStats    StatsSnapshot `json:"global_stats"`
	ByRoute        map[string]RouteSummary `json:"by_route"`
}

type RouteSummary struct {
	SessionCount  int    `json:"session_count"`
	PacketsSent   uint64 `json:"packets_sent"`
	PacketsRecv   uint64 `json:"packets_received"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
}

func (s *SessionStats) Summary() Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	summary := Summary{
		ActiveSessions: len(s.sessions),
		GlobalStats:    s.globalStats.Snapshot(),
		ByRoute:        make(map[string]RouteSummary),
	}
	
	for _, info := range s.sessions {
		snap := info.Stats.Snapshot()
		rs := summary.ByRoute[info.Route]
		rs.SessionCount++
		rs.PacketsSent += snap.PacketsSent
		rs.PacketsRecv += snap.PacketsReceived
		rs.BytesSent += snap.BytesSent
		rs.BytesReceived += snap.BytesReceived
		summary.ByRoute[info.Route] = rs
	}
	
	return summary
}

// StartCleanupLoop starts a background cleanup goroutine.
func (s *SessionStats) StartCleanupLoop(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		interval = time.Minute
	}
	
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				s.Cleanup()
			}
		}
	}()
}
