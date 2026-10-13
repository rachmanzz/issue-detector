package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestLoadFileRegexRule(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "no-println.yaml")
	content := `id: ACME-001
category: quality
severity: medium
title: println debug
message: jangan pakai println
fix_hint: gunakan logger
confidence: 0.9
languages: [go]
match:
  kind: regex
  pattern: '\bfmt\.Println\('
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "ACME-001" || r.Category != model.CategoryQuality || r.Severity != model.SeverityMedium {
		t.Fatalf("metadata mismatch: %+v", r.Rule)
	}
	if r.Confidence != 0.9 {
		t.Errorf("confidence = %v, want 0.9", r.Confidence)
	}
	f := strFile("x.go", model.LanguageGo, "package main", `fmt.Println("hi")`)
	m, err := r.Matcher.Match(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m[0].Line != 2 {
		t.Fatalf("want match at line 2, got %+v", m)
	}
}

func TestLoadFileASTRule(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "py-eval.yaml")
	content := `id: ACME-002
category: security
severity: high
title: eval
match:
  kind: ast
  query: "(call function: (identifier) @f)"
languages: [python]
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Confidence != 0.7 {
		t.Errorf("default confidence = %v, want 0.7", r.Confidence)
	}
	f := strFile("x.py", model.LanguagePython, "eval(x)")
	if m, err := r.Matcher.Match(context.Background(), f); err != nil || len(m) == 0 {
		t.Fatalf("ast rule should match: m=%v err=%v", m, err)
	}
}

func TestLoadFileInvalid(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"no-id.yaml":    "category: quality\nseverity: low\nmatch: {kind: regex, pattern: x}\n",
		"bad-cat.yaml":  "id: X\ncategory: nope\nseverity: low\nmatch: {kind: regex, pattern: x}\n",
		"bad-kind.yaml": "id: X\ncategory: quality\nseverity: low\nmatch: {kind: wat}\n",
	}
	for name, content := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(p); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestLoadPathsDir(t *testing.T) {
	dir := t.TempDir()
	content := `id: ACME-003
category: todo
severity: low
match: {kind: regex, pattern: 'x'}
`
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].ID != "ACME-003" {
		t.Fatalf("got %+v", rs)
	}
}
