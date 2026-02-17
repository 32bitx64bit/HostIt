package updater

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"hostit/shared/version"
)

type Manager struct {
	Repo      string
	Component Component
	AssetName string
	ModuleDir string
	Store     *Store
	// Preserve is kept for backwards compatibility; prefer PreservePaths.
	Preserve      string
	PreservePaths []string
	Now           func() time.Time
	Restart       func() error
	CheckEvery    time.Duration

	mu sync.Mutex
	st persistedState
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

func (m *Manager) ApplyLocal(ctx context.Context, componentZipPath string, sharedZipPath string) (bool, error) {
	_ = ctx
	m.mu.Lock()
	if m.st.Job.State == JobRunning {
		m.mu.Unlock()
		return false, nil
	}
	m.mu.Unlock()

	componentZipPath = strings.TrimSpace(componentZipPath)
	if componentZipPath == "" {
		return false, errors.New("missing component zip")
	}

	compStaged, err := copyZipToTemp(componentZipPath, "hostit-local-component-*")
	if err != nil {
		return false, err
	}

	sharedStaged := ""
	if strings.TrimSpace(sharedZipPath) != "" {
		sharedStaged, err = copyZipToTemp(sharedZipPath, "hostit-local-shared-*")
		if err != nil {
			_ = os.Remove(compStaged)
			return false, err
		}
	}

	m.mu.Lock()
	m.st.Job = JobStatus{State: JobRunning, TargetVersion: "local", StartedAtUnix: m.Now().Unix()}
	_ = m.Store.Save(m.st)
	m.mu.Unlock()

	go m.runApplyLocal(compStaged, sharedStaged)
	return true, nil
}

func (m *Manager) runApply(targetVersion string, assetURL string) {
	logw := newJobLogWriter(m, 1<<20, 500*time.Millisecond)

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

	preserve := make([]string, 0, 1+len(m.PreservePaths))
	if strings.TrimSpace(m.Preserve) != "" {
		preserve = append(preserve, m.Preserve)
	}
	for _, p := range m.PreservePaths {
		if strings.TrimSpace(p) != "" {
			preserve = append(preserve, p)
		}
	}

	err := ApplyZipUpdate(ctx, ApplyOptions{
		AssetURL:       assetURL,
		ModuleDir:      m.ModuleDir,
		ExpectedFolder: expectedFolder,
		PreservePath:   m.Preserve,
		PreservePaths:  preserve,
		SharedDestDir:  siblingSharedDir(m.ModuleDir),
	}, logw)

	now := m.Now().Unix()
	m.mu.Lock()
	if err != nil {
		m.st.Job.State = JobFailed
		m.st.Job.EndedAtUnix = now
		m.st.Job.LastError = err.Error()
		m.st.Job.Log = logw.String()
		_ = m.Store.Save(m.st)
		m.mu.Unlock()
		return
	}
	m.st.Job.State = JobSuccess
	m.st.Job.EndedAtUnix = now
	m.st.Job.Log = logw.String()
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

func (m *Manager) runApplyLocal(componentZipPath string, sharedZipPath string) {
	defer os.Remove(componentZipPath)
	if strings.TrimSpace(sharedZipPath) != "" {
		defer os.Remove(sharedZipPath)
	}

	logw := newJobLogWriter(m, 1<<20, 500*time.Millisecond)

	ctx := context.Background()
	sharedDest := siblingSharedDir(m.ModuleDir)
	if strings.TrimSpace(sharedZipPath) != "" && strings.TrimSpace(sharedDest) != "" {
		_, _ = fmt.Fprintf(logw, "Applying local shared.zip update...\n")
		if err := ApplySharedZipFileUpdate(sharedZipPath, sharedDest, logw); err != nil {
			_, _ = fmt.Fprintf(logw, "Shared update failed: %v\n", err)
		}
	}

	expectedFolder := ""
	switch m.Component {
	case ComponentServer:
		expectedFolder = "server"
	case ComponentClient:
		expectedFolder = "client"
	}

	preserve := make([]string, 0, 1+len(m.PreservePaths))
	if strings.TrimSpace(m.Preserve) != "" {
		preserve = append(preserve, m.Preserve)
	}
	for _, p := range m.PreservePaths {
		if strings.TrimSpace(p) != "" {
			preserve = append(preserve, p)
		}
	}

	err := ApplyZipFileUpdate(ctx, componentZipPath, ApplyOptions{
		ModuleDir:      m.ModuleDir,
		ExpectedFolder: expectedFolder,
		PreservePath:   m.Preserve,
		PreservePaths:  preserve,
		SharedDestDir:  siblingSharedDir(m.ModuleDir),
	}, logw)

	now := m.Now().Unix()
	m.mu.Lock()
	if err != nil {
		m.st.Job.State = JobFailed
		m.st.Job.EndedAtUnix = now
		m.st.Job.LastError = err.Error()
		m.st.Job.Log = logw.String()
		_ = m.Store.Save(m.st)
		m.mu.Unlock()
		return
	}
	m.st.Job.State = JobSuccess
	m.st.Job.EndedAtUnix = now
	m.st.Job.Log = logw.String()
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

func copyZipToTemp(srcPath string, pattern string) (string, error) {
	srcPath = strings.TrimSpace(srcPath)
	if srcPath == "" {
		return "", errors.New("missing zip path")
	}
	abs, err := filepath.Abs(srcPath)
	if err != nil {
		return "", err
	}
	src, err := os.Open(abs)
	if err != nil {
		return "", err
	}
	defer src.Close()

	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := os.Chmod(tmpName, fs.FileMode(0o644)); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	return tmpName, nil
}

type jobLogWriter struct {
	m *Manager

	mu          sync.Mutex
	buf         bytes.Buffer
	remaining   int
	minPersist  time.Duration
	lastPersist time.Time
}

func newJobLogWriter(m *Manager, limitBytes int, minPersist time.Duration) *jobLogWriter {
	if minPersist <= 0 {
		minPersist = 500 * time.Millisecond
	}
	return &jobLogWriter{m: m, remaining: limitBytes, minPersist: minPersist}
}

func (w *jobLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Enforce an upper bound on log size while still returning len(p)
	// so callers don't treat this as a write failure.
	if w.remaining > 0 {
		toWrite := p
		if len(toWrite) > w.remaining {
			toWrite = toWrite[:w.remaining]
		}
		_, _ = w.buf.Write(toWrite)
		w.remaining -= len(toWrite)
	}

	now := time.Now()
	if w.lastPersist.IsZero() || now.Sub(w.lastPersist) >= w.minPersist {
		w.persistLocked(now)
	}
	return len(p), nil
}

func (w *jobLogWriter) persistLocked(now time.Time) {
	// Avoid hammering disk; only persist while the job is running.
	w.m.mu.Lock()
	if w.m.st.Job.State == JobRunning {
		w.m.st.Job.Log = w.buf.String()
		_ = w.m.Store.Save(w.m.st)
	}
	w.m.mu.Unlock()
	w.lastPersist = now
}

func (w *jobLogWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
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
