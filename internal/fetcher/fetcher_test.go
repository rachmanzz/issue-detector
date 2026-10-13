package fetcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for path, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnumerateIgnores(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"a.go":                 "package a\n",
		"node_modules/x.js":    "x\n",
		"vendor/y.go":          "package y\n",
		"generated/out.min.js": "z\n",
		".gitignore":           "generated/\n*.min.js\n",
		"keep.txt":             "hello\n",
	})

	entries, err := Enumerate(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, e := range entries {
		got[e.RelPath] = true
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %v, want a.go + .gitignore + keep.txt", got)
	}
	for _, want := range []string{"a.go", ".gitignore", "keep.txt"} {
		if !got[want] {
			t.Errorf("missing %s (%v)", want, got)
		}
	}
	for _, nope := range []string{"node_modules/x.js", "vendor/y.go", "generated/out.min.js"} {
		if got[nope] {
			t.Errorf("should be ignored: %s", nope)
		}
	}
}

func TestFetchLocalDir(t *testing.T) {
	dir := t.TempDir()
	root, cleanup, err := Fetch(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if root == "" {
		t.Error("empty root")
	}
}

func TestFetchMissingDir(t *testing.T) {
	if _, _, err := Fetch(context.Background(), Options{Root: "/definitely/not/here"}); err == nil {
		t.Error("expected error for missing dir")
	}
}
