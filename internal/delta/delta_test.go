package delta

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func commitAll(t *testing.T, dir string) {
	t.Helper()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.AddGlob("."); err != nil {
		t.Fatal(err)
	}
	_, err = wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@e", When: time.Unix(0, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFromBase(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.py", "line1\nline2\nline3\n")
	commitAll(t, dir)

	// Modify line 2 and add a new file (uncommitted).
	write("app.py", "line1\nCHANGED\nline3\n")
	write("new.py", "print('new')\n")

	set, err := FromBase(context.Background(), dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains("app.py", 2) {
		t.Errorf("line 2 should be changed: %+v", set.Files)
	}
	if set.Contains("app.py", 1) || set.Contains("app.py", 3) {
		t.Errorf("unchanged lines flagged: %+v", set.Files)
	}
	if !set.New["new.py"] || !set.Contains("new.py", 99) {
		t.Errorf("new.py should be entirely new: %+v", set.New)
	}
}

func TestFromPatchFile(t *testing.T) {
	patch := `diff --git a/x.go b/x.go
index 111..222 100644
--- a/x.go
+++ b/x.go
@@ -1,3 +1,4 @@
 package main
 
+// TODO: added
 var x = 1
`
	dir := t.TempDir()
	p := filepath.Join(dir, "c.diff")
	if err := os.WriteFile(p, []byte(patch), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := FromPatchFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains("x.go", 3) {
		t.Errorf("added line 3 should be in diff: %+v", set.Files)
	}
	if set.Contains("x.go", 1) {
		t.Errorf("context line 1 should not be flagged: %+v", set.Files)
	}
	if set.New["x.go"] {
		t.Errorf("x.go is a modification, not a new file")
	}
}
