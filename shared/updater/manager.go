package updater

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"hostit/shared/version"
)

type Manager struct {
	Repo       string
	Component  Component
	AssetName  string
	ModuleDir  string
	Store      *Store
	Preserve   string
	Now        func() time.Time
	Restart    func() error
	CheckEvery time.Duration

	mu   sync.Mutex
	st   persistedState
}

func NewManager(repo string, component Component, assetName string, moduleDir string, storePath string) *Manager {
	m := &Manager{
		Repo:       repo,
		Component:  component,
		AssetName:  assetName,
		ModuleDir:  moduleDir,
		Store:      &Store{Path: storePath},
		Now:        time.Now,
		CheckEvery: 30 * time.Minute,
	}
	st, _ := m.Store.Load()
	m.st = st
	if m.st.Job.State == "" {
		m.st.Job.State = JobIdle
	}
	return m
}

func (m *Manager) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(m.CheckEvery)
		defer t.Stop()
		m.CheckIfDue(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.CheckIfDue(ctx)
			}
		}
	}()
}

func (m *Manager) CheckIfDue(ctx context.Context) {
	m.mu.Lock()
	last := time.Unix(m.st.LastCheckUnix, 0)
	freq := m.CheckEvery
	if freq <= 0 {
		freq = 30 * time.Minute
	}
	should := m.st.LastCheckUnix == 0 || m.Now().Sub(last) >= freq
	m.mu.Unlock()
	if should {
		_ = m.CheckNow(ctx)
	}
}

func (m *Manager) CheckNow(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	rel, err := fetchLatestStableRelease(ctx, m.Repo)
	if err != nil {
		m.mu.Lock()
		m.st.LastCheckUnix = m.Now().Unix()
		_ = m.Store.Save(m.st)
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.st.LastCheckUnix = m.Now().Unix()
	m.st.AvailableVersion = strings.TrimSpace(rel.TagName)
	m.st.AvailableURL = strings.TrimSpace(rel.HTMLURL)
	_ = m.Store.Save(m.st)
	m.mu.Unlock()
	return nil
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur := version.CurrentParsed
	availStr := strings.TrimSpace(m.st.AvailableVersion)
	availV, ok := version.Parse(availStr)
	updateAvailable := ok && availV.Compare(cur) > 0

	now := m.Now().Unix()
	suppressed := false
	if m.st.RemindUntilUnix > now {
		suppressed = true
	}
	if strings.TrimSpace(m.st.SkipVersion) != "" && strings.EqualFold(strings.TrimSpace(m.st.SkipVersion), availStr) {
		suppressed = true
	}
	show := updateAvailable && !suppressed && m.st.Job.State != JobRunning

	return Status{
		CurrentVersion:   version.Current,
		AvailableVersion: availStr,
		AvailableURL:     m.st.AvailableURL,
		CheckedAtUnix:    m.st.LastCheckUnix,
		RemindUntilUnix:  m.st.RemindUntilUnix,
		SkipVersion:      m.st.SkipVersion,
		UpdateAvailable:  updateAvailable,
		Suppressed:       suppressed,
		ShowPopup:        show,
		Job:              m.st.Job,
	}
}

func (m *Manager) RemindLater(d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st.RemindUntilUnix = m.Now().Add(d).Unix()
	return m.Store.Save(m.st)
}

func (m *Manager) SkipAvailableVersion() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st.SkipVersion = strings.TrimSpace(m.st.AvailableVersion)
	return m.Store.Save(m.st)
}

func (m *Manager) Apply(ctx context.Context) (bool, error) {
	m.mu.Lock()
	if m.st.Job.State == JobRunning {
		m.mu.Unlock()
		return false, nil
	}
	availStr := strings.TrimSpace(m.st.AvailableVersion)
	availV, ok := version.Parse(availStr)
	if !ok {
		m.mu.Unlock()
		return false, errors.New("no available version")
	}
	if availV.Compare(version.CurrentParsed) <= 0 {
		m.mu.Unlock()
		return false, errors.New("already up to date")
	}
	assetURL := ""
	// refresh release to get asset URLs
	m.mu.Unlock()

	ctx2, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	rel, err := fetchLatestStableRelease(ctx2, m.Repo)
	if err != nil {
		return false, err
	}
	assetURL = findAssetURL(rel, m.AssetName)
	if strings.TrimSpace(assetURL) == "" {
		return false, fmt.Errorf("missing asset %q on release", m.AssetName)
	}

	m.mu.Lock()
	m.st.Job = JobStatus{State: JobRunning, TargetVersion: availStr, StartedAtUnix: m.Now().Unix()}
	_ = m.Store.Save(m.st)
	m.mu.Unlock()

	go m.runApply(availStr, assetURL)
	return true, nil
}

func (m *Manager) runApply(targetVersion string, assetURL string) {
	var buf bytes.Buffer
	logw := &limitedWriter{W: &buf, N: 1 << 20}

	ctx := context.Background()
	if err := m.CheckNow(ctx); err != nil {
		_, _ = fmt.Fprintf(logw, "Check error (continuing): %v\n", err)
	}

	// If the release includes a shared.zip asset, apply it into the sibling shared module
	// before building the component.
	sharedDest := siblingSharedDir(m.ModuleDir)
	if strings.TrimSpace(sharedDest) != "" {
		ctxShared, cancel := context.WithTimeout(ctx, 12*time.Second)
		rel, err := fetchLatestStableRelease(ctxShared, m.Repo)
		cancel()
		if err != nil {
			_, _ = fmt.Fprintf(logw, "Fetch release for shared.zip failed (continuing): %v\n", err)
		} else {
			sharedURL := findAssetURL(rel, "shared.zip")
			if strings.TrimSpace(sharedURL) != "" {
				_, _ = fmt.Fprintf(logw, "Applying shared.zip update...\n")
				if err := ApplySharedZipUpdate(ctx, sharedURL, sharedDest, logw); err != nil {
					_, _ = fmt.Fprintf(logw, "Shared update failed: %v\n", err)
					// Don't hard-fail: allow component update to proceed; build may still succeed.
				}
			} else {
				_, _ = fmt.Fprintf(logw, "No shared.zip asset found on release (continuing).\n")
			}
		}
	}

	expectedFolder := ""
	switch m.Component {
	case ComponentServer:
		expectedFolder = "server"
	case ComponentClient:
		expectedFolder = "client"
	}

	err := ApplyZipUpdate(ctx, ApplyOptions{
		AssetURL:       assetURL,
		ModuleDir:      m.ModuleDir,
		ExpectedFolder: expectedFolder,
		PreservePath:   m.Preserve,
		SharedDestDir:  siblingSharedDir(m.ModuleDir),
	}, logw)

	now := m.Now().Unix()
	m.mu.Lock()
	if err != nil {
		m.st.Job.State = JobFailed
		m.st.Job.EndedAtUnix = now
		m.st.Job.LastError = err.Error()
		m.st.Job.Log = buf.String()
		_ = m.Store.Save(m.st)
		m.mu.Unlock()
		return
	}
	m.st.Job.State = JobSuccess
	m.st.Job.EndedAtUnix = now
	m.st.Job.Log = buf.String()
	m.st.Job.LastError = ""
	m.st.RemindUntilUnix = 0
	m.st.SkipVersion = ""
	_ = m.Store.Save(m.st)
	restart := m.Restart
	m.mu.Unlock()

	if restart != nil {
		m.mu.Lock()
		m.st.Job.Restarting = true
		_ = m.Store.Save(m.st)
		m.mu.Unlock()
		if err := restart(); err != nil {
			m.mu.Lock()
			m.st.Job.State = JobFailed
			m.st.Job.LastError = "restart failed: " + err.Error()
			m.st.Job.Log = m.st.Job.Log + "\nRestart failed: " + err.Error() + "\n"
			m.st.Job.EndedAtUnix = m.Now().Unix()
			_ = m.Store.Save(m.st)
			m.mu.Unlock()
		}
	}
}

func siblingSharedDir(moduleDir string) string {
	moduleDir = strings.TrimSpace(moduleDir)
	if moduleDir == "" {
		return ""
	}
	parent := filepath.Dir(moduleDir)
	if strings.TrimSpace(parent) == "" {
		return ""
	}
	shared := filepath.Join(parent, "shared")
	if fi, err := os.Stat(shared); err == nil && fi.IsDir() {
		return shared
	}
	// If it doesn't exist yet, still return the intended path so the updater
	// can create it when the release zip includes shared/.
	return shared
}

type limitedWriter struct {
	W io.Writer
	N int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.N <= 0 {
		return len(p), nil
	}
	if len(p) > lw.N {
		p = p[:lw.N]
	}
	n, err := lw.W.Write(p)
	lw.N -= n
	return len(p), err
}

func (m *Manager) BuiltBinaryPath() string {
	name := ""
	if m.Component == ComponentServer {
		name = "tunnel-server"
	} else {
		name = "tunnel-agent"
	}
	return filepath.Join(m.ModuleDir, "bin", name)
}
