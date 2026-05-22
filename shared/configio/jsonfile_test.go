package configio

import (
	"os"
	"path/filepath"
	"testing"
)

type TestConfig struct {
	Name    string            `json:"name"`
	Value   int               `json:"value"`
	Enabled bool              `json:"enabled"`
	Tags    []string          `json:"tags"`
	Nested  NestedConfig      `json:"nested"`
	Extras  map[string]string `json:"extras"`
}

type NestedConfig struct {
	Inner string `json:"inner"`
}

func TestLoad(t *testing.T) {
	t.Run("existing valid JSON file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		content := `{"name": "test", "value": 42, "enabled": true}`
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("setup: write file: %v", err)
		}

		var cfg TestConfig
		found, err := Load(path, &cfg)
		if err != nil {
			t.Fatalf("Load() error = %v, want nil", err)
		}
		if !found {
			t.Fatalf("Load() found = false, want true")
		}
		if cfg.Name != "test" || cfg.Value != 42 || !cfg.Enabled {
			t.Errorf("Load() config = %+v, want populated struct", cfg)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "missing.json")

		var cfg TestConfig
		found, err := Load(path, &cfg)
		if err != nil {
			t.Fatalf("Load() error = %v, want nil", err)
		}
		if found {
			t.Fatalf("Load() found = true, want false")
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte(`{invalid`), 0o644); err != nil {
			t.Fatalf("setup: write file: %v", err)
		}

		var cfg TestConfig
		found, err := Load(path, &cfg)
		if err == nil {
			t.Fatalf("Load() error = nil, want error")
		}
		if !found {
			t.Fatalf("Load() found = false, want true (file exists even if parse fails)")
		}
	})

	t.Run("defaults preserved for missing fields", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "partial.json")
		if err := os.WriteFile(path, []byte(`{"name": "partial"}`), 0o644); err != nil {
			t.Fatalf("setup: write file: %v", err)
		}

		cfg := TestConfig{Value: 99, Enabled: true}
		found, err := Load(path, &cfg)
		if err != nil {
			t.Fatalf("Load() error = %v, want nil", err)
		}
		if !found {
			t.Fatalf("Load() found = false, want true")
		}
		if cfg.Name != "partial" {
			t.Errorf("cfg.Name = %q, want %q", cfg.Name, "partial")
		}
		if cfg.Value != 99 {
			t.Errorf("cfg.Value = %d, want %d (default preserved)", cfg.Value, 99)
		}
		if !cfg.Enabled {
			t.Errorf("cfg.Enabled = false, want true (default preserved)")
		}
	})

	t.Run("empty path", func(t *testing.T) {
		var cfg TestConfig
		found, err := Load("", &cfg)
		if err != nil {
			t.Fatalf("Load() error = %v, want nil", err)
		}
		if found {
			t.Fatalf("Load() found = true, want false")
		}
	})
}

func TestSave(t *testing.T) {
	t.Run("save to new file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		cfg := TestConfig{Name: "new", Value: 1}

		if err := Save(path, cfg); err != nil {
			t.Fatalf("Save() error = %v, want nil", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat() error = %v, want nil", err)
		}
		if info.IsDir() {
			t.Fatalf("Save() created a directory, want file")
		}
	})

	t.Run("save over existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(`{"name": "old"}`), 0o644); err != nil {
			t.Fatalf("setup: write file: %v", err)
		}

		cfg := TestConfig{Name: "new", Value: 2}
		if err := Save(path, cfg); err != nil {
			t.Fatalf("Save() error = %v, want nil", err)
		}

		var loaded TestConfig
		if _, err := Load(path, &loaded); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if loaded.Name != "new" || loaded.Value != 2 {
			t.Errorf("loaded config = %+v, want updated values", loaded)
		}
	})

	t.Run("empty path", func(t *testing.T) {
		cfg := TestConfig{Name: "test"}
		if err := Save("", cfg); err == nil {
			t.Fatalf("Save() error = nil, want error")
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "a", "b", "c", "config.json")
		cfg := TestConfig{Name: "deep"}

		if err := Save(path, cfg); err != nil {
			t.Fatalf("Save() error = %v, want nil", err)
		}

		if _, err := os.Stat(path); err != nil {
			t.Fatalf("file not found: %v", err)
		}
	})

	t.Run("produces valid reloadable JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		cfg := TestConfig{
			Name:    "roundtrip",
			Value:   123,
			Enabled: true,
			Tags:    []string{"a", "b"},
			Nested:  NestedConfig{Inner: "x"},
			Extras:  map[string]string{"key": "val"},
		}

		if err := Save(path, cfg); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		var loaded TestConfig
		found, err := Load(path, &loaded)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if !found {
			t.Fatalf("Load() found = false, want true")
		}
		if loaded.Name != cfg.Name || loaded.Value != cfg.Value || loaded.Enabled != cfg.Enabled {
			t.Errorf("loaded config = %+v, want %+v", loaded, cfg)
		}
	})
}

func TestRoundTrip(t *testing.T) {
	t.Run("save then load equivalent", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		original := TestConfig{
			Name:    "roundtrip",
			Value:   42,
			Enabled: false,
			Tags:    []string{"one", "two", "three"},
			Nested:  NestedConfig{Inner: "nested_value"},
			Extras:  map[string]string{"foo": "bar", "baz": "qux"},
		}

		if err := Save(path, original); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		var loaded TestConfig
		if _, err := Load(path, &loaded); err != nil {
			t.Fatalf("Load() error = %v", err)
		}

		if loaded.Name != original.Name {
			t.Errorf("Name = %q, want %q", loaded.Name, original.Name)
		}
		if loaded.Value != original.Value {
			t.Errorf("Value = %d, want %d", loaded.Value, original.Value)
		}
		if loaded.Enabled != original.Enabled {
			t.Errorf("Enabled = %v, want %v", loaded.Enabled, original.Enabled)
		}
		if len(loaded.Tags) != len(original.Tags) {
			t.Errorf("Tags = %v, want %v", loaded.Tags, original.Tags)
		} else {
			for i := range loaded.Tags {
				if loaded.Tags[i] != original.Tags[i] {
					t.Errorf("Tags[%d] = %q, want %q", i, loaded.Tags[i], original.Tags[i])
				}
			}
		}
		if loaded.Nested.Inner != original.Nested.Inner {
			t.Errorf("Nested.Inner = %q, want %q", loaded.Nested.Inner, original.Nested.Inner)
		}
		if len(loaded.Extras) != len(original.Extras) {
			t.Errorf("Extras = %v, want %v", loaded.Extras, original.Extras)
		} else {
			for k, v := range original.Extras {
				if loaded.Extras[k] != v {
					t.Errorf("Extras[%q] = %q, want %q", k, loaded.Extras[k], v)
				}
			}
		}
	})

	t.Run("multiple saves don't corrupt", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")

		for i := 0; i < 5; i++ {
			cfg := TestConfig{Name: "iteration", Value: i}
			if err := Save(path, cfg); err != nil {
				t.Fatalf("Save() iteration %d error = %v", i, err)
			}
		}

		var loaded TestConfig
		if _, err := Load(path, &loaded); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if loaded.Value != 4 {
			t.Errorf("Value = %d, want 4 (last written)", loaded.Value)
		}
	})
}

func TestFilePermissions(t *testing.T) {
	t.Run("saved file is readable and writable", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		cfg := TestConfig{Name: "perm"}

		if err := Save(path, cfg); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}

		mode := info.Mode().Perm()
		if mode&0o400 == 0 {
			t.Errorf("file not readable by owner: mode = %o", mode)
		}
		if mode&0o200 == 0 {
			t.Errorf("file not writable by owner: mode = %o", mode)
		}
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("nil config pointer", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(`{"name": "test"}`), 0o644); err != nil {
			t.Fatalf("setup: write file: %v", err)
		}

		_, err := Load(path, nil)
		if err == nil {
			t.Fatalf("Load() with nil dst error = nil, want error")
		}
	})

	t.Run("load directory path returns error", func(t *testing.T) {
		dir := t.TempDir()
		var cfg TestConfig
		_, err := Load(dir, &cfg)
		if err == nil {
			t.Fatalf("Load() directory path error = nil, want error")
		}
	})

	t.Run("save unmarshalable value returns error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		bad := make(chan int)
		if err := Save(path, bad); err == nil {
			t.Fatalf("Save() unmarshalable error = nil, want error")
		}
	})

	t.Run("very large config", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "large.json")

		largeTags := make([]string, 10000)
		for i := range largeTags {
			largeTags[i] = "tag_value_that_is_reasonably_long_to_increase_size"
		}
		cfg := TestConfig{
			Name:  "large",
			Tags:  largeTags,
			Extras: make(map[string]string),
		}
		for i := 0; i < 1000; i++ {
			cfg.Extras["key_"+string(rune('a'+i%26))+string(rune('0'+i/26))] = "value_that_adds_some_length"
		}

		if err := Save(path, cfg); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		var loaded TestConfig
		found, err := Load(path, &loaded)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if !found {
			t.Fatalf("Load() found = false, want true")
		}
		if len(loaded.Tags) != len(cfg.Tags) {
			t.Errorf("len(Tags) = %d, want %d", len(loaded.Tags), len(cfg.Tags))
		}
		if len(loaded.Extras) != len(cfg.Extras) {
			t.Errorf("len(Extras) = %d, want %d", len(loaded.Extras), len(cfg.Extras))
		}
	})

	t.Run("special characters in values", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "special.json")
		cfg := TestConfig{
			Name:  "hello\nworld\ttab\"quote\\backslash",
			Value: 1,
			Extras: map[string]string{
				"unicode": "日本語",
				"emoji":   "🚀",
				"html":    "<script>alert('xss')</script>",
			},
		}

		if err := Save(path, cfg); err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		var loaded TestConfig
		if _, err := Load(path, &loaded); err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if loaded.Name != cfg.Name {
			t.Errorf("Name = %q, want %q", loaded.Name, cfg.Name)
		}
		for k, v := range cfg.Extras {
			if loaded.Extras[k] != v {
				t.Errorf("Extras[%q] = %q, want %q", k, loaded.Extras[k], v)
			}
		}
	})
}
