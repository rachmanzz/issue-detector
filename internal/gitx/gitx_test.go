package gitx

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func initRepoWith(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add(name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@e", When: time.Unix(0, 0)},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzeSensitiveAndMissing(t *testing.T) {
	dir := t.TempDir()
	initRepoWith(t, dir, map[string]string{
		"app.go":    "package main\n",
		".env":      "SECRET=x\n",
		"keys.pem":  "-----BEGIN PRIVATE KEY-----\n",
		"README.md": "# hi\n",
	})

	fs := Analyze(context.Background(), dir, DefaultOptions(1024*1024))
	ids := map[string]int{}
	for _, f := range fs {
		ids[f.RuleID]++
	}
	if ids["GIT-001"] < 2 {
		t.Errorf("expected sensitive files flagged (GIT-001), got %v", ids)
	}
	if ids["GIT-004"] == 0 {
		t.Errorf("missing LICENSE should be flagged (GIT-004), got %v", ids)
	}
	if ids["GIT-003"] != 0 {
		t.Errorf("README present, GIT-003 should not fire, got %v", ids)
	}
	if ids["GIT-005"] == 0 {
		t.Errorf("missing .gitignore should be flagged (GIT-005), got %v", ids)
	}
}

func TestAnalyzeNonRepo(t *testing.T) {
	dir := t.TempDir()
	if fs := Analyze(context.Background(), dir, DefaultOptions(1024)); fs != nil {
		t.Errorf("non-repo should yield no findings, got %+v", fs)
	}
}
