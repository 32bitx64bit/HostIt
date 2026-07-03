package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed theme.css components.js app.js
var FS embed.FS

// Content-hash ETags let browsers revalidate cheaply (304) while picking up
// new assets immediately after a binary update; embedded files carry no
// modtime, so http.FileServer cannot do this on its own.
var etags = func() map[string]string {
	m := make(map[string]string)
	entries, err := FS.ReadDir(".")
	if err != nil {
		return m
	}
	for _, e := range entries {
		b, err := FS.ReadFile(e.Name())
		if err != nil {
			continue
		}
		sum := sha256.Sum256(b)
		m[e.Name()] = `"` + hex.EncodeToString(sum[:8]) + `"`
	}
	return m
}()

func Handler() http.Handler {
	sub, err := fs.Sub(FS, ".")
	if err != nil {
		panic("web: cannot create sub filesystem: " + err.Error())
	}
	return http.StripPrefix("/static/", headerHandler(http.FileServer(http.FS(sub))))
}

func headerHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		}
		w.Header().Set("Cache-Control", "no-cache")
		if et, ok := etags[strings.TrimPrefix(r.URL.Path, "/")]; ok {
			w.Header().Set("ETag", et)
		}
		h.ServeHTTP(w, r)
	})
}
