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

func relSet(t *testing.T, dir string, opts Options) map[string]bool {
	t.Helper()
	entries, err := Enumerate(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.RelPath] = true
	}
	return got
}

// TestEnumerateGitignoreNegation guards that a "!" re-include works even though
// another pattern would otherwise ignore the file.
func TestEnumerateGitignoreNegation(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		".gitignore": "*.log\n!keep.log\n",
		"a.log":      "x\n",
		"keep.log":   "y\n",
		"main.go":    "package main\n",
	})
	got := relSet(t, dir, Options{})
	if !got["keep.log"] {
		t.Errorf("negated keep.log must be kept, got %v", got)
	}
	if got["a.log"] {
		t.Errorf("a.log must be ignored, got %v", got)
	}
}

// TestEnumerateGitignoreCRLF guards that CRLF ignore files still match.
func TestEnumerateGitignoreCRLF(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		".gitignore": "*.min.js\r\ngen/\r\n",
		"a.min.js":   "z\n",
		"gen/out.go": "package g\n",
		"main.go":    "package main\n",
	})
	got := relSet(t, dir, Options{})
	if got["a.min.js"] || got["gen/out.go"] {
		t.Errorf("CRLF patterns must ignore a.min.js and gen/out.go, got %v", got)
	}
	if !got["main.go"] {
		t.Errorf("main.go must remain, got %v", got)
	}
}

// TestEnumerateNestedGitignore guards that a nested .gitignore applies to its
// subtree only.
func TestEnumerateNestedGitignore(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"sub/.gitignore": "*.tmp\n",
		"sub/a.tmp":      "x\n",
		"sub/keep.go":    "package s\n",
		"root.tmp":       "y\n",
	})
	got := relSet(t, dir, Options{})
	if got["sub/a.tmp"] {
		t.Errorf("nested .gitignore must ignore sub/a.tmp, got %v", got)
	}
	if !got["root.tmp"] {
		t.Errorf("nested pattern must not affect root.tmp, got %v", got)
	}
	if !got["sub/keep.go"] {
		t.Errorf("sub/keep.go must remain, got %v", got)
	}
}
