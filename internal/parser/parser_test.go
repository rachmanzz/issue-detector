package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestDetectLanguage(t *testing.T) {
	cases := map[string]model.Language{
		"x.go":      model.LanguageGo,
		"main.py":   model.LanguagePython,
		"app.js":    model.LanguageJavaScript,
		"comp.tsx":  model.LanguageTypeScript,
		"README.md": model.LanguageUnknown,
	}
	for path, want := range cases {
		if got := DetectLanguage(path); got != want {
			t.Errorf("DetectLanguage(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestReadFileSkipsBinaryAndOversize(t *testing.T) {
	dir := t.TempDir()

	png := filepath.Join(dir, "img.png")
	if err := os.WriteFile(png, []byte{0x89, 0x50, 0x4e, 0x47, 1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFile(png, "img.png", int64(len([]byte{0x89, 0x50, 0x4e, 0x47, 1, 2, 3})), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Binary {
		t.Error("png should be flagged binary")
	}

	big := filepath.Join(dir, "big.txt")
	content := make([]byte, 64)
	if err := os.WriteFile(big, content, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err = ReadFile(big, "big.txt", 64, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Skipped {
		t.Error("oversize file should be skipped")
	}
}

func TestReadFileLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("one\r\ntwo\nthree"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	f, err := ReadFile(p, "a.txt", st.Size(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Lines) != 3 {
		t.Fatalf("want 3 lines, got %d", len(f.Lines))
	}
	if f.Line(2) != "two" {
		t.Errorf("Line(2) = %q", f.Line(2))
	}
}
