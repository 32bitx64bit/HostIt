package updater

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ApplyOptions struct {
	AssetURL       string
	ModuleDir      string
	ExpectedFolder string   // "server" or "client"; empty means module root
	PreservePaths  []string // additional absolute paths to preserve (files or directories)
	SharedDestDir  string   // optional absolute path to shared module destination
}

func ApplyZipUpdate(ctx context.Context, opts ApplyOptions, logw io.Writer) error {
	if strings.TrimSpace(opts.AssetURL) == "" {
		return errors.New("missing asset URL")
	}
	if strings.TrimSpace(opts.ModuleDir) == "" {
		return errors.New("missing module dir")
	}
	moduleDir, err := filepath.Abs(opts.ModuleDir)
	if err != nil {
		return err
	}

	// Create temp dir inside moduleDir to allow fast os.Rename across same filesystem
	tmpDir, err := os.MkdirTemp(moduleDir, ".hostit-update-*")
	if err != nil {
		// Fallback to system temp dir
		tmpDir, err = os.MkdirTemp("", "hostit-update-*")
		if err != nil {
			return err
		}
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, "update.zip")
	if err := downloadToFile(ctx, opts.AssetURL, zipPath, logw); err != nil {
		return err
	}

	extractDir := filepath.Join(tmpDir, "unzipped")
	if err := unzip(zipPath, extractDir); err != nil {
		return err
	}

	srcRoot, err := pickSourceRoot(extractDir, opts.ExpectedFolder)
	if err != nil {
		return err
	}

	sharedDest := strings.TrimSpace(opts.SharedDestDir)
	if sharedDest != "" {
		if p, err := filepath.Abs(sharedDest); err == nil {
			sharedDest = p
		}
		sharedSrc, err := pickSharedRoot(extractDir)
		if err != nil {
			_, _ = fmt.Fprintf(logw, "Shared source not found in zip (continuing): %v\n", err)
		} else {
			_, _ = fmt.Fprintf(logw, "Applying shared into: %s\n", sharedDest)
			if err := syncDir(sharedSrc, sharedDest, nil, nil, logw); err != nil {
				return err
			}
		}
	}

	_, _ = fmt.Fprintf(logw, "Extracted source: %s\n", srcRoot)
	_, _ = fmt.Fprintf(logw, "Applying into: %s\n", moduleDir)

	preserve := make([]string, 0, len(opts.PreservePaths))
	for _, p := range opts.PreservePaths {
		if strings.TrimSpace(p) != "" {
			preserve = append(preserve, p)
		}
	}

	var extraSkip []string
	if srcRoot == extractDir && sharedDest != "" {
		extraSkip = append(extraSkip, "shared")
	}

	if err := syncDir(srcRoot, moduleDir, preserve, extraSkip, logw); err != nil {
		return err
	}

	if err := runBuild(ctx, moduleDir, logw); err != nil {
		return err
	}

	return nil
}

// ApplyZipFileUpdate applies an update from a local zip file path.
func ApplyZipFileUpdate(ctx context.Context, zipPath string, opts ApplyOptions, logw io.Writer) error {
	if strings.TrimSpace(zipPath) == "" {
		return errors.New("missing zip path")
	}
	if strings.TrimSpace(opts.ModuleDir) == "" {
		return errors.New("missing module dir")
	}
	moduleDir, err := filepath.Abs(opts.ModuleDir)
	if err != nil {
		return err
	}
	zipPath, err = filepath.Abs(strings.TrimSpace(zipPath))
	if err != nil {
		return err
	}
	if _, err := os.Stat(zipPath); err != nil {
		return err
	}

	// Create temp dir inside moduleDir to allow fast os.Rename across same filesystem
	tmpDir, err := os.MkdirTemp(moduleDir, ".hostit-update-local-*")
	if err != nil {
		tmpDir, err = os.MkdirTemp("", "hostit-update-local-*")
		if err != nil {
			return err
		}
	}
	defer os.RemoveAll(tmpDir)

	_, _ = fmt.Fprintf(logw, "Using local zip: %s\n", zipPath)

	extractDir := filepath.Join(tmpDir, "unzipped")
	if err := unzip(zipPath, extractDir); err != nil {
		return err
	}

	srcRoot, err := pickSourceRoot(extractDir, opts.ExpectedFolder)
	if err != nil {
		return err
	}

	sharedDest := strings.TrimSpace(opts.SharedDestDir)
	if sharedDest != "" {
		if p, err := filepath.Abs(sharedDest); err == nil {
			sharedDest = p
		}
		sharedSrc, err := pickSharedRoot(extractDir)
		if err != nil {
			_, _ = fmt.Fprintf(logw, "Shared source not found in zip (continuing): %v\n", err)
		} else {
			_, _ = fmt.Fprintf(logw, "Applying shared into: %s\n", sharedDest)
			if err := syncDir(sharedSrc, sharedDest, nil, nil, logw); err != nil {
				return err
			}
		}
	}

	_, _ = fmt.Fprintf(logw, "Extracted source: %s\n", srcRoot)
	_, _ = fmt.Fprintf(logw, "Applying into: %s\n", moduleDir)

	preserve := make([]string, 0, len(opts.PreservePaths))
	for _, p := range opts.PreservePaths {
		if strings.TrimSpace(p) != "" {
			preserve = append(preserve, p)
		}
	}

	var extraSkip []string
	if srcRoot == extractDir && sharedDest != "" {
		extraSkip = append(extraSkip, "shared")
	}

	if err := syncDir(srcRoot, moduleDir, preserve, extraSkip, logw); err != nil {
		return err
	}

	if err := runBuild(ctx, moduleDir, logw); err != nil {
		return err
	}

	return nil
}

// ApplySharedZipUpdate downloads a zip asset that contains the shared module (shared/go.mod)
// and syncs it into sharedDestDir. It does not run build scripts.
func ApplySharedZipUpdate(ctx context.Context, assetURL string, sharedDestDir string, logw io.Writer) error {
	if strings.TrimSpace(assetURL) == "" {
		return errors.New("missing asset URL")
	}
	if strings.TrimSpace(sharedDestDir) == "" {
		return errors.New("missing shared dest dir")
	}
	sharedDestDir, err := filepath.Abs(sharedDestDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sharedDestDir, 0o755); err != nil {
		return err
	}

	// Create temp dir inside sharedDestDir to allow fast os.Rename across same filesystem
	tmpDir, err := os.MkdirTemp(sharedDestDir, ".hostit-update-shared-*")
	if err != nil {
		tmpDir, err = os.MkdirTemp("", "hostit-update-shared-*")
		if err != nil {
			return err
		}
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, "shared.zip")
	if err := downloadToFile(ctx, assetURL, zipPath, logw); err != nil {
		return err
	}

	extractDir := filepath.Join(tmpDir, "unzipped")
	if err := unzip(zipPath, extractDir); err != nil {
		return err
	}

	sharedSrc, err := pickSharedRoot(extractDir)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(logw, "Extracted shared: %s\n", sharedSrc)
	_, _ = fmt.Fprintf(logw, "Applying shared into: %s\n", sharedDestDir)
	return syncDir(sharedSrc, sharedDestDir, nil, nil, logw)
}

// ApplySharedZipFileUpdate applies shared module files from a local zip path.
func ApplySharedZipFileUpdate(zipPath string, sharedDestDir string, logw io.Writer) error {
	if strings.TrimSpace(zipPath) == "" {
		return errors.New("missing zip path")
	}
	if strings.TrimSpace(sharedDestDir) == "" {
		return errors.New("missing shared dest dir")
	}
	sharedDestDir, err := filepath.Abs(sharedDestDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sharedDestDir, 0o755); err != nil {
		return err
	}
	zipPath, err = filepath.Abs(strings.TrimSpace(zipPath))
	if err != nil {
		return err
	}
	if _, err := os.Stat(zipPath); err != nil {
		return err
	}

	// Create temp dir inside sharedDestDir to allow fast os.Rename across same filesystem
	tmpDir, err := os.MkdirTemp(sharedDestDir, ".hostit-update-local-shared-*")
	if err != nil {
		tmpDir, err = os.MkdirTemp("", "hostit-update-local-shared-*")
		if err != nil {
			return err
		}
	}
	defer os.RemoveAll(tmpDir)

	_, _ = fmt.Fprintf(logw, "Using local shared zip: %s\n", zipPath)

	extractDir := filepath.Join(tmpDir, "unzipped")
	if err := unzip(zipPath, extractDir); err != nil {
		return err
	}

	sharedSrc, err := pickSharedRoot(extractDir)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(logw, "Extracted shared: %s\n", sharedSrc)
	_, _ = fmt.Fprintf(logw, "Applying shared into: %s\n", sharedDestDir)
	return syncDir(sharedSrc, sharedDestDir, nil, nil, logw)
}

func pickSharedRoot(extractDir string) (string, error) {
	// Common case: zip includes top-level shared/go.mod.
	cand := filepath.Join(extractDir, "shared")
	if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
		if _, err := os.Stat(filepath.Join(cand, "go.mod")); err == nil {
			return cand, nil
		}
	}

	// Fallback: search a few levels deep for a directory named 'shared' containing go.mod.
	// (Release zips sometimes wrap content in an extra top folder.)
	best := ""
	_ = filepath.WalkDir(extractDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(extractDir, path)
		if err != nil {
			return nil
		}
		depth := 0
		if rel != "." {
			depth = len(strings.Split(rel, string(os.PathSeparator)))
		}
		if depth > 4 {
			return filepath.SkipDir
		}
		if filepath.Base(path) != "shared" {
			return nil
		}
		if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
			best = path
			return filepath.SkipDir
		}
		return nil
	})
	if best != "" {
		return best, nil
	}
	return "", errors.New("could not locate shared/go.mod in extracted zip")
}

func downloadToFile(ctx context.Context, url string, dst string, logw io.Writer) error {
	_, _ = fmt.Fprintf(logw, "Downloading: %s\n", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "hostit-updater")
	cl := &http.Client{Timeout: 0}
	res, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("download http %d", res.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, res.Body); err != nil {
		return err
	}
	fi, err := f.Stat()
	if err == nil {
		_, _ = fmt.Fprintf(logw, "Downloaded %d bytes\n", fi.Size())
	}
	return nil
}

func unzip(zipPath string, dstDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(r.File))
	sem := make(chan struct{}, 10) // limit concurrency

	for _, f := range r.File {
		f := f
		name := f.Name
		if strings.Contains(name, "..") {
			// basic zip-slip defense
			continue
		}
		p := filepath.Join(dstDir, filepath.FromSlash(name))
		if !strings.HasPrefix(filepath.Clean(p), filepath.Clean(dstDir)+string(os.PathSeparator)) {
			continue
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}

		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			rc, err := f.Open()
			if err != nil {
				errCh <- err
				return
			}
			defer rc.Close()
			out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
			if err != nil {
				errCh <- err
				return
			}
			defer out.Close()
			if _, err := io.Copy(out, rc); err != nil {
				errCh <- err
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func pickSourceRoot(extractDir string, expectedFolder string) (string, error) {
	if expectedFolder != "" {
		cand := filepath.Join(extractDir, expectedFolder)
		if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
			if _, err := os.Stat(filepath.Join(cand, "build.sh")); err == nil {
				return cand, nil
			}
		}

		// If expectedFolder is provided but not found at the root, check if the zip
		// was extracted with a single top-level wrapper folder (common in GitHub releases).
		ents, err := os.ReadDir(extractDir)
		if err == nil && len(ents) == 1 && ents[0].IsDir() {
			wrapperCand := filepath.Join(extractDir, ents[0].Name(), expectedFolder)
			if fi, err := os.Stat(wrapperCand); err == nil && fi.IsDir() {
				if _, err := os.Stat(filepath.Join(wrapperCand, "build.sh")); err == nil {
					return wrapperCand, nil
				}
			}
		}

		return "", fmt.Errorf("could not locate expected folder %q with build.sh in extracted zip", expectedFolder)
	}

	// if build.sh exists at root, use root
	if _, err := os.Stat(filepath.Join(extractDir, "build.sh")); err == nil {
		return extractDir, nil
	}
	// fallback: try to find a single folder containing build.sh
	ents, err := os.ReadDir(extractDir)
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		cand := filepath.Join(extractDir, e.Name())
		if _, err := os.Stat(filepath.Join(cand, "build.sh")); err == nil {
			return cand, nil
		}
	}
	return "", errors.New("could not locate build.sh in extracted zip")
}

func syncDir(srcRoot string, dstRoot string, preserveAbsList []string, extraSkipPrefixes []string, logw io.Writer) error {
	preserveFiles := make(map[string]struct{})
	preserveDirs := make([]string, 0)
	for _, p := range preserveAbsList {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if st, err := os.Stat(abs); err == nil && st.IsDir() {
			preserveDirs = append(preserveDirs, filepath.Clean(abs)+string(os.PathSeparator))
			continue
		}
		preserveFiles[filepath.Clean(abs)] = struct{}{}
	}

	skipPrefixes := []string{".git", "bin"}
	skipPrefixes = append(skipPrefixes, extraSkipPrefixes...)

	// First pass: collect all relative paths from source
	srcRelPaths := make(map[string]struct{})
	err := filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.Clean(rel)
		parts := strings.Split(rel, string(os.PathSeparator))
		if len(parts) > 0 {
			for _, sp := range skipPrefixes {
				if parts[0] == sp {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
			if strings.HasPrefix(parts[0], ".hostit-update-") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		srcRelPaths[rel] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}

	// Second pass: delete files in dst that don't exist in src
	dstAbs, err := filepath.Abs(dstRoot)
	if err != nil {
		return err
	}
	dstAbs = filepath.Clean(dstAbs)

	toDelete := make([]string, 0)
	err = filepath.WalkDir(dstRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(dstRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.Clean(rel)
		parts := strings.Split(rel, string(os.PathSeparator))
		if len(parts) > 0 {
			for _, sp := range skipPrefixes {
				if parts[0] == sp {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
			if strings.HasPrefix(parts[0], ".hostit-update-") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		abs := filepath.Clean(path)

		// Check if this path should be preserved
		if _, ok := preserveFiles[abs]; ok {
			return nil
		}
		for _, dirPrefix := range preserveDirs {
			if strings.HasPrefix(abs+string(os.PathSeparator), dirPrefix) {
				return nil
			}
		}

		// If not in source, mark for deletion
		if _, exists := srcRelPaths[rel]; !exists {
			toDelete = append(toDelete, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Delete files/directories not in source (delete in reverse order for dirs)
	for i := len(toDelete) - 1; i >= 0; i-- {
		path := toDelete[i]
		if err := removeAllWritable(path, dstAbs); err != nil {
			_, _ = fmt.Fprintf(logw, "Warning: failed to remove %s: %v\n", path, err)
		} else {
			_, _ = fmt.Fprintf(logw, "Removed stale file: %s\n", path)
		}
	}

	// Third pass: copy files from source to destination
	var wg sync.WaitGroup
	errCh := make(chan error, 1000)
	sem := make(chan struct{}, 10) // limit concurrency

	err = filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.Clean(rel)
		parts := strings.Split(rel, string(os.PathSeparator))
		if len(parts) > 0 {
			for _, sp := range skipPrefixes {
				if parts[0] == sp {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
			if strings.HasPrefix(parts[0], ".hostit-update-") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		dstPath := filepath.Join(dstRoot, rel)
		if abs, err := filepath.Abs(dstPath); err == nil {
			abs = filepath.Clean(abs)
			if _, ok := preserveFiles[abs]; ok {
				return nil
			}
			for _, dirPrefix := range preserveDirs {
				if strings.HasPrefix(abs+string(os.PathSeparator), dirPrefix) {
					return nil
				}
			}
		}

		if d.IsDir() {
			if err := os.MkdirAll(dstPath, 0o755); err != nil {
				if os.IsPermission(err) {
					_ = ensureWritablePath(filepath.Dir(dstPath), dstAbs)
					if err2 := os.MkdirAll(dstPath, 0o755); err2 == nil {
						return nil
					}
				}
				return err
			}
			return nil
		}

		si, err := os.Stat(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			if os.IsPermission(err) {
				_ = ensureWritablePath(filepath.Dir(dstPath), dstAbs)
				if err2 := os.MkdirAll(filepath.Dir(dstPath), 0o755); err2 == nil {
					// continue
				} else {
					return err
				}
			} else {
				return err
			}
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(path, dstPath string, mode os.FileMode) {
			defer wg.Done()
			defer func() { <-sem }()

			// Try fast rename first
			_ = os.Remove(dstPath) // Remove existing file to avoid issues on Windows
			if err := os.Rename(path, dstPath); err == nil {
				return
			}

			// Fallback to copy
			in, err := os.Open(path)
			if err != nil {
				errCh <- err
				return
			}
			defer in.Close()
			out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				if os.IsPermission(err) {
					_ = ensureWritablePath(dstPath, dstAbs)
					_ = ensureWritablePath(filepath.Dir(dstPath), dstAbs)
					out, err = os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
				}
				if err != nil {
					errCh <- err
					return
				}
			}
			defer out.Close()
			if _, err := io.Copy(out, in); err != nil {
				errCh <- err
				return
			}
		}(path, dstPath, si.Mode())

		return nil
	})

	if err != nil {
		return err
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func removeAllWritable(path string, dstRoot string) error {
	if err := os.RemoveAll(path); err == nil {
		return nil
	} else if !os.IsPermission(err) {
		return err
	}

	_ = ensureWritablePath(path, dstRoot)
	_ = makeTreeWritable(path)
	_ = ensureWritablePath(filepath.Dir(path), dstRoot)
	return os.RemoveAll(path)
}

func makeTreeWritable(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		_ = makeWritable(path)
		return nil
	})
}

func ensureWritablePath(path string, dstRoot string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	root := filepath.Clean(dstRoot)
	if root != "" {
		if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
			return nil
		}
	}
	return makeWritable(abs)
}

func makeWritable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return nil
	}
	newMode := mode
	if mode.IsDir() {
		newMode = mode | 0o700
	} else {
		newMode = mode | 0o600
	}
	if newMode == mode {
		return nil
	}
	return os.Chmod(path, newMode)
}

func runBuild(ctx context.Context, moduleDir string, logw io.Writer) error {
	_, _ = fmt.Fprintf(logw, "Running build.sh...\n")
	cmd := execCommandContext(ctx, "sh", "./build.sh")
	cmd.Dir = moduleDir
	cmd.Stdout = logw
	cmd.Stderr = logw
	cmd.Env = ensureGoBuildEnv(os.Environ(), moduleDir)
	start := time.Now()
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintf(logw, "Build failed after %s\n", time.Since(start).Truncate(10*time.Millisecond))
		return err
	}
	_, _ = fmt.Fprintf(logw, "Build succeeded in %s\n", time.Since(start).Truncate(10*time.Millisecond))
	return nil
}

func ensureGoBuildEnv(env []string, moduleDir string) []string {
	get := func(key string) string {
		prefix := key + "="
		for i := len(env) - 1; i >= 0; i-- {
			if strings.HasPrefix(env[i], prefix) {
				return strings.TrimPrefix(env[i], prefix)
			}
		}
		return ""
	}
	setIfMissing := func(key, val string) {
		if strings.TrimSpace(val) == "" {
			return
		}
		if strings.TrimSpace(get(key)) != "" {
			return
		}
		env = append(env, key+"="+val)
	}

	home := strings.TrimSpace(get("HOME"))
	if home == "" {
		// systemd services often have HOME unset; Go 1.24+ needs a module cache.
		// Use a writable fallback.
		home = moduleDir
	}
	setIfMissing("HOME", home)

	gopath := strings.TrimSpace(get("GOPATH"))
	if gopath == "" {
		gopath = filepath.Join(home, "go")
	}
	setIfMissing("GOPATH", gopath)

	gomodcache := strings.TrimSpace(get("GOMODCACHE"))
	if gomodcache == "" {
		gomodcache = filepath.Join(gopath, "pkg", "mod")
	}
	setIfMissing("GOMODCACHE", gomodcache)

	return env
}
