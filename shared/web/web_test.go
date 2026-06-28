package web

import (
	"io/fs"
	"testing"
)

func TestStaticAssetsExist(t *testing.T) {
	for _, name := range []string{"theme.css", "components.js", "app.js"} {
		data, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Fatalf("missing embedded static asset %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("embedded static asset %s is empty", name)
		}
	}
}

func TestComponentsExportEmber(t *testing.T) {
	data, err := fs.ReadFile(FS, "components.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{"Ember", "panel", "tile", "badge", "button", "chart", "table", "routeCard", "checkItem", "updatePopup"} {
		if !contains(s, want) {
			t.Errorf("components.js missing %q", want)
		}
	}
}

func TestAppJSHasHelpers(t *testing.T) {
	data, err := fs.ReadFile(FS, "app.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{"styleSelects", "initTheme", "initTabs", "drawBars", "bindToggleLabel", "setStatus", "pushLog", "initClock"} {
		if !contains(s, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
}

func TestThemeCSSHasVariables(t *testing.T) {
	data, err := fs.ReadFile(FS, "theme.css")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{"--bg0", "--yellow", "--green", "--red", "data-theme=\"light\"", "data-theme=\"dark\""} {
		if !contains(s, want) {
			t.Errorf("theme.css missing %q", want)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
