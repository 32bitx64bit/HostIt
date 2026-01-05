package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"hostit/shared/version"
)

type githubRelease struct {
	TagName    string        `json:"tag_name"`
	HTMLURL    string        `json:"html_url"`
	Prerelease bool          `json:"prerelease"`
	Assets     []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

func fetchLatestStableRelease(ctx context.Context, repo string) (githubRelease, error) {
	// Use /releases to skip prereleases.
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return githubRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "hostit-updater")

	cl := &http.Client{Timeout: 10 * time.Second}
	res, err := cl.Do(req)
	if err != nil {
		return githubRelease{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("github releases http %d", res.StatusCode)
	}
	var rels []githubRelease
	if err := json.NewDecoder(res.Body).Decode(&rels); err != nil {
		return githubRelease{}, err
	}
	for _, r := range rels {
		if r.Prerelease {
			continue
		}
		if _, ok := version.Parse(r.TagName); ok {
			return r, nil
		}
	}
	return githubRelease{}, errors.New("no stable release found")
}

func findAssetURL(rel githubRelease, assetName string) string {
	for _, a := range rel.Assets {
		if a.Name == assetName {
			return a.BrowserDownloadURL
		}
	}
	return ""
}
