package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func fixedNow() func() time.Time {
	ts := time.Date(2026, 10, 14, 1, 2, 3, 0, time.UTC)
	return func() time.Time { return ts }
}

func readRegisterar(t *testing.T, path string) registerar {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("registerar tidak ada: %v", err)
	}
	var rr registerar
	if err := json.Unmarshal(b, &rr); err != nil {
		t.Fatalf("registerar invalid: %v", err)
	}
	return rr
}

func TestRegisterNonGitTwoItems(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "b.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exe := filepath.Join(t.TempDir(), "issue-detector")
	store, err := Open(Options{Mode: "local", ExePath: exe, Now: fixedNow()})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.Register(project, "0.1.0-test"); err != nil {
		t.Fatal(err)
	}

	// Registry must reference the session once.
	regData, err := os.ReadFile(filepath.Join(store.Dir(), registryFile))
	if err != nil {
		t.Fatal(err)
	}
	var reg registry
	if err := json.Unmarshal(regData, &reg); err != nil {
		t.Fatal(err)
	}
	if reg.AppVersion != "0.1.0-test" || len(reg.Registery) != 1 {
		t.Fatalf("registry mismatch: %+v", reg)
	}
	id := SessionID(project)
	if reg.Registery[0].ID != id || reg.Registery[0].ProjectPath != project {
		t.Fatalf("registry entry mismatch: %+v want id=%s path=%s", reg.Registery[0], id, project)
	}

	rrPath := filepath.Join(store.Dir(), sessionPrefix+id, registerarFile)
	rr := readRegisterar(t, rrPath)
	if rr.SessionID != id || len(rr.Items) != 1 {
		t.Fatalf("registerar mismatch: %+v", rr)
	}
	first := rr.Items[0]
	if len(first.CommitIDs) != 0 {
		t.Errorf("non-git should have no commits: %v", first.CommitIDs)
	}
	if len(first.UncommitFiles) != 2 {
		t.Fatalf("want 2 uncommitted files, got %d: %+v", len(first.UncommitFiles), first.UncommitFiles)
	}

	// A no-op rescan must NOT grow the log (idempotent).
	{
		res, err := store.Register(project, "0.1.0-test")
		if err != nil {
			t.Fatal(err)
		}
		if !res.Skipped {
			t.Errorf("unchanged rescan should be skipped: %+v", res)
		}
		if got := readRegisterar(t, rrPath); len(got.Items) != 1 {
			t.Errorf("skipped rescan grew log: %d items", len(got.Items))
		}
	}

	// Changing a file must change its hash in the next item.
	if err := os.WriteFile(filepath.Join(project, "a.go"), []byte("package a\n\nvar X = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Register(project, "0.1.0-test"); err != nil {
		t.Fatal(err)
	}
	rr = readRegisterar(t, rrPath)
	if len(rr.Items) != 2 {
		t.Fatalf("want 2 items after second scan, got %d", len(rr.Items))
	}
	h1 := fileHash(first.UncommitFiles, "a.go")
	h2 := fileHash(rr.Items[1].UncommitFiles, "a.go")
	if h1 == "" || h2 == "" || h1 == h2 {
		t.Errorf("a.go hash should change: %q -> %q", h1, h2)
	}

	// Registry stays a single entry (no duplicates).
	regData, _ = os.ReadFile(filepath.Join(store.Dir(), registryFile))
	_ = json.Unmarshal(regData, &reg)
	if len(reg.Registery) != 1 {
		t.Errorf("registry should not duplicate sessions: %+v", reg.Registery)
	}
}

func TestRegisterGit(t *testing.T) {
	project := t.TempDir()
	repo, err := git.PlainInit(project, false)
	if err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(project, "main.go")
	if err := os.WriteFile(main, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("main.go"); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit("first", &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@t", When: fixedNow()()},
	}); err != nil {
		t.Fatal(err)
	}

	// Uncommitted modification + untracked file.
	if err := os.WriteFile(main, []byte("package main\n\nvar X = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "new.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exe := filepath.Join(t.TempDir(), "issue-detector")
	store, err := Open(Options{Mode: "local", ExePath: exe, Now: fixedNow()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Register(project, "v"); err != nil {
		t.Fatal(err)
	}

	id := SessionID(project)
	rr := readRegisterar(t, filepath.Join(store.Dir(), sessionPrefix+id, registerarFile))
	if len(rr.Items) != 1 {
		t.Fatalf("want 1 item, got %d", len(rr.Items))
	}
	item := rr.Items[0]
	if len(item.CommitIDs) != 1 {
		t.Fatalf("want 1 new commit, got %v", item.CommitIDs)
	}
	if fileHash(item.UncommitFiles, "main.go") == "" {
		t.Errorf("main.go should be tracked as uncommitted: %+v", item.UncommitFiles)
	}
	if fileHash(item.UncommitFiles, "new.go") == "" {
		t.Errorf("new.go should be tracked as untracked: %+v", item.UncommitFiles)
	}

	// Second register: no new commits, same uncommitted set → skipped.
	res2, err := store.Register(project, "v")
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Skipped {
		t.Errorf("idempotent rescan should be skipped: %+v", res2)
	}
	rr = readRegisterar(t, filepath.Join(store.Dir(), sessionPrefix+id, registerarFile))
	if len(rr.Items) != 1 {
		t.Fatalf("idempotent rescan grew log: want 1 item, got %d", len(rr.Items))
	}
}

func TestResolveDirModes(t *testing.T) {
	home := t.TempDir()
	globalWant := filepath.Join(home, ".issues_detector", "cache")

	if got, err := resolveDir(Options{Mode: "global", Home: home}); err != nil || got != globalWant {
		t.Errorf("global = %q,%v want %q", got, err, globalWant)
	}

	exe := filepath.Join(t.TempDir(), "issue-detector")
	localWant := filepath.Join(filepath.Dir(exe), ".issues_detector")
	if got, err := resolveDir(Options{Mode: "local", ExePath: exe}); err != nil || got != localWant {
		t.Errorf("local = %q,%v want %q", got, err, localWant)
	}

	// auto (and empty) default to the per-user global dir, never project-local.
	binExe := filepath.Join(home, "bin", "issue-detector")
	if got, err := resolveDir(Options{Mode: "auto", ExePath: binExe, Home: home}); err != nil || got != globalWant {
		t.Errorf("auto(bin) = %q,%v want %q", got, err, globalWant)
	}
	if got, err := resolveDir(Options{Mode: "auto", ExePath: exe, Home: home}); err != nil || got != globalWant {
		t.Errorf("auto(custom) = %q,%v want %q", got, err, globalWant)
	}
	if got, err := resolveDir(Options{Home: home}); err != nil || got != globalWant {
		t.Errorf("empty mode = %q,%v want %q", got, err, globalWant)
	}

	// custom path wins over mode.
	if got, _ := resolveDir(Options{Mode: "global", Home: home, Path: "/tmp/custom-x"}); got != "/tmp/custom-x" {
		t.Errorf("custom path = %q", got)
	}

	// env override wins over everything.
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", "/tmp/env-x")
	if got, _ := resolveDir(Options{Mode: "global", Home: home, Path: "/tmp/custom-x"}); got != "/tmp/env-x" {
		t.Errorf("env override = %q", got)
	}
}

func TestSessionIDStable(t *testing.T) {
	a := SessionID("/a/b")
	if a != SessionID("/a/b") {
		t.Error("SessionID not stable")
	}
	if a == SessionID("/a/c") {
		t.Error("SessionID collision on different paths")
	}
}

func TestRetentionCap(t *testing.T) {
	project := t.TempDir()
	f := filepath.Join(project, "a.go")
	exe := filepath.Join(t.TempDir(), "issue-detector")
	store, err := Open(Options{Mode: "local", ExePath: exe, Now: fixedNow(), MaxItems: 3})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if err := os.WriteFile(f, []byte(fmt.Sprintf("package a\n// rev %d\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Register(project, "v"); err != nil {
			t.Fatal(err)
		}
	}
	rr := readRegisterar(t, filepath.Join(store.Dir(), sessionPrefix+SessionID(project), registerarFile))
	if len(rr.Items) != 3 {
		t.Fatalf("retention cap: want 3 items, got %d", len(rr.Items))
	}
	// Newest item must reflect the last revision (rev 5).
	if fileHash(rr.Items[len(rr.Items)-1].UncommitFiles, "a.go") == "" {
		t.Errorf("newest item missing a.go: %+v", rr.Items)
	}
}

func TestRuleSetKeyInvalidates(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "issue-detector")
	s1, _ := Open(Options{Mode: "local", ExePath: exe, Now: fixedNow(), RuleSetHash: "rules-a"})
	if _, err := s1.Register(project, "v"); err != nil {
		t.Fatal(err)
	}
	// Same files but different rule set → new item (not skipped).
	s2, _ := Open(Options{Mode: "local", ExePath: exe, Now: fixedNow(), RuleSetHash: "rules-b"})
	res, err := s2.Register(project, "v")
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Error("rule-set change must not be skipped")
	}
	rr := readRegisterar(t, filepath.Join(s2.Dir(), sessionPrefix+SessionID(project), registerarFile))
	if len(rr.Items) != 2 || rr.Items[1].RuleSetHash != "rules-b" {
		t.Fatalf("rule-set key not recorded: %+v", rr.Items)
	}
}

func TestChangedReader(t *testing.T) {
	project := t.TempDir()
	f := filepath.Join(project, "a.go")
	if err := os.WriteFile(f, []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "issue-detector")
	store, _ := Open(Options{Mode: "local", ExePath: exe, Now: fixedNow()})
	if _, err := store.Register(project, "v"); err != nil {
		t.Fatal(err)
	}
	// No change → empty delta.
	_, changed, err := store.Changed(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Errorf("no-change delta should be empty: %+v", changed)
	}
	// Modify → delta reports the file.
	if err := os.WriteFile(f, []byte("package a\nvar Y=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, changed, err = store.Changed(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0].File != "a.go" || changed[0].Hash == "" {
		t.Errorf("delta should report a.go: %+v", changed)
	}
	last, ok, err := store.LastItem(project)
	if err != nil || !ok {
		t.Fatalf("LastItem: ok=%v err=%v", ok, err)
	}
	if last.ToolVersion != "v" {
		t.Errorf("last item tool version = %q", last.ToolVersion)
	}
}

func TestConcurrentRegister(t *testing.T) {
	project := t.TempDir()
	exe := filepath.Join(t.TempDir(), "issue-detector")
	// Two independent Store instances (as two CLI/serve goroutines would have).
	s1, _ := Open(Options{Mode: "local", ExePath: exe, Now: fixedNow()})
	s2, _ := Open(Options{Mode: "local", ExePath: exe, Now: fixedNow()})

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, s := range []*Store{s1, s2} {
		wg.Add(1)
		go func(i int, st *Store) {
			defer wg.Done()
			_, errs[i] = st.Register(project, "v")
		}(i, s)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}
	// Registry must have exactly one entry (no lost/duplicated writes).
	reg := readRegistry(t, s1.Dir())
	if len(reg.Registery) != 1 {
		t.Fatalf("registry entries = %d, want 1: %+v", len(reg.Registery), reg.Registery)
	}
	if reg.Registery[0].ID != SessionID(project) {
		t.Fatalf("wrong session entry: %+v", reg.Registery)
	}
}

func readRegistry(t *testing.T, dir string) registry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, registryFile))
	if err != nil {
		t.Fatalf("registry tidak ada: %v", err)
	}
	var r registry
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("registry invalid: %v", err)
	}
	return r
}

func fileHash(files []UncommitFile, name string) string {
	for _, f := range files {
		if f.File == name {
			return f.Hash
		}
	}
	return ""
}
