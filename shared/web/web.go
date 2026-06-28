package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed theme.css components.js app.js
var FS embed.FS

func Handler() http.Handler {
	sub, err := fs.Sub(FS, ".")
	if err != nil {
		panic("web: cannot create sub filesystem: " + err.Error())
	}
	return http.StripPrefix("/static/", contentTypeHandler(http.FileServer(http.FS(sub))))
}

func contentTypeHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}
