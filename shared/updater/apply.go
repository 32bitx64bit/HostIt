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
	"time"
)

type ApplyOptions struct {
	AssetURL       string
	ModuleDir      string
	ExpectedFolder string // "server" or "client"; empty means module root
	PreservePath   string // absolute path to preserve (e.g. config file)
	SharedDestDir  string // optional absolute path to shared module destination
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

	tmpDir, err := os.MkdirTemp("", "hostit-update-*")
	if err != nil {
		return err
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
			if err := syncDir(sharedSrc, sharedDest, "", logw); err != nil {
				return err
			}
		}
	}

	_, _ = fmt.Fprintf(logw, "Extracted source: %s\n", srcRoot)
	_, _ = fmt.Fprintf(logw, "Applying into: %s\n", moduleDir)

	if err := syncDir(srcRoot, moduleDir, opts.PreservePath, logw); err != nil {
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

	tmpDir, err := os.MkdirTemp("", "hostit-update-shared-*")
	if err != nil {
		return err
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
	return syncDir(sharedSrc, sharedDestDir, "", logw)
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
	for _, f := range r.File {
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
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		rc.Close()
		out.Close()
		if copyErr != nil {
			return copyErr
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

func syncDir(srcRoot string, dstRoot string, preserveAbs string, logw io.Writer) error {
	preserveAbs = strings.TrimSpace(preserveAbs)
	if preserveAbs != "" {
		p, err := filepath.Abs(preserveAbs)
		if err == nil {
			preserveAbs = p
		}
	}

	skipPrefixes := []string{".git", "bin"}

	return filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, err error) error {
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
		}

		dstPath := filepath.Join(dstRoot, rel)
		if preserveAbs != "" {
			if abs, err := filepath.Abs(dstPath); err == nil && abs == preserveAbs {
				return nil
			}
		}

		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}

		si, err := os.Stat(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, si.Mode())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		return nil
	})
}

func runBuild(ctx context.Context, moduleDir string, logw io.Writer) error {
	_, _ = fmt.Fprintf(logw, "Running build.sh...\n")
	cmd := execCommandContext(ctx, "sh", "./build.sh")
	cmd.Dir = moduleDir
	cmd.Stdout = logw
	cmd.Stderr = logw
	start := time.Now()
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintf(logw, "Build failed after %s\n", time.Since(start).Truncate(10*time.Millisecond))
		return err
	}
	_, _ = fmt.Fprintf(logw, "Build succeeded in %s\n", time.Since(start).Truncate(10*time.Millisecond))
	return nil
}
