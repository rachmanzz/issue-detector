package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/rachmanzz/issue-detector/internal/cache"
	"github.com/rachmanzz/issue-detector/internal/model"
)

// TestScanHonorsYAMLConfig guards the regression where YAML keys
// (severity_min/no_git/…) were clobbered by flag defaults.
func TestScanHonorsYAMLConfig(t *testing.T) {
	// Keep the session cache out of the developer's real home dir.
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())

	dir := t.TempDir()
	must := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("keys.pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n") // critical
	must("app.js", "console.log('debug')\n")                                           // low
	// .yml extension must also be auto-detected.
	must("issue-detector.yml", "severity_min: critical\nno_git: true\n")

	out := filepath.Join(t.TempDir(), "report.json")
	root := NewRootCmd()
	root.SetArgs([]string{
		"scan", dir,
		"--no-deps", "--no-adapters",
		"-f", "json", "-o", out,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("scan gagal: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("report tidak ada: %v", err)
	}
	var res model.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("harusnya ada temuan critical dari severity_min")
	}
	for _, f := range res.Findings {
		if model.SeverityWeight[f.Severity] < model.SeverityWeight[model.SeverityCritical] {
			t.Errorf("severity_min dari YAML tidak dihormati: %+v", f)
		}
	}
	if res.Summary.FilesEnumerated < 2 {
		t.Errorf("enumerated = %d, want >= 2", res.Summary.FilesEnumerated)
	}
}

// TestScanAIOnly exercises the full --ai-only path against a fake
// OpenAI-compatible endpoint: the AI is the sole detector and its findings +
// narrative land in the report.
func TestScanAIOnly(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		prompt := ""
		if len(body.Messages) > 0 {
			prompt = body.Messages[len(body.Messages)-1].Content
		}
		content := "prioritas: hapus rahasia dari source"
		if strings.Contains(prompt, "STRICT JSON") {
			content = `{"findings":[{"line":3,"severity":"critical","category":"secrets","title":"Hardcoded secret","message":"m","fix":"env","confidence":0.9}]}`
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": content}}},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte("package main\n\nconst apiKey = \"sk-abc\"\n\nfunc main() { println(apiKey) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "o.json")
	root := NewRootCmd()
	root.SetArgs([]string{
		"scan", dir,
		"--ai-only", "--ai-base-url", srv.URL, "--ai-model", "m",
		"--no-deps", "--no-adapters", "-f", "json", "-o", out,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("scan --ai-only gagal: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep model.ScanResult
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.AISummary == "" {
		t.Error("ai_summary kosong")
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(rep.Findings))
	}
	if rep.Findings[0].Source != model.SourceAI {
		t.Errorf("source = %q, want ai", rep.Findings[0].Source)
	}
	if rep.Findings[0].Line != 3 {
		t.Errorf("line = %d, want 3", rep.Findings[0].Line)
	}
}

// TestScanAIOnlyIncrementalFromCache verifies that a second --ai-only run with
// no changes diffs against the cached HEAD and sends no files, and that an
// uncommitted edit makes only the changed file flow to the detector again.
func TestScanAIOnlyIncrementalFromCache(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		prompt := ""
		if len(body.Messages) > 0 {
			prompt = body.Messages[len(body.Messages)-1].Content
		}
		reply := "ringkasan"
		if strings.Contains(prompt, "STRICT JSON") {
			reply = `{"findings":[{"line":1,"severity":"high","category":"quality","title":"t","message":"m","confidence":0.7}]}`
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": reply}}},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "main.go")
	if err := os.WriteFile(main, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("main.go"); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@t", When: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}

	run := func() model.ScanResult {
		out := filepath.Join(t.TempDir(), "o.json")
		root := NewRootCmd()
		root.SetArgs([]string{
			"scan", dir,
			"--ai-only", "--ai-base-url", srv.URL, "--ai-model", "m",
			"--no-deps", "--no-adapters", "-f", "json", "-o", out,
		})
		if err := root.Execute(); err != nil {
			t.Fatalf("scan --ai-only gagal: %v", err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var rep model.ScanResult
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}

	if got := run().Summary.FilesEnumerated; got != 1 {
		t.Fatalf("run pertama: files = %d, want 1 (full scan)", got)
	}
	// No changes since the cached HEAD: nothing should be sent.
	if got := run().Summary.FilesEnumerated; got != 0 {
		t.Errorf("run kedua: files = %d, want 0 (incremental, no changes)", got)
	}
	// Uncommitted edit must be picked up as an incremental change.
	if err := os.WriteFile(main, []byte("package main\n\nfunc main() { println(1) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := run().Summary.FilesEnumerated; got != 1 {
		t.Errorf("run ketiga: files = %d, want 1 (uncommitted change)", got)
	}
}

// TestDeltaScanNotCachedAsFull guards that an explicit --base delta is not
// persisted as result.json (it is filtered to the change set and would be
// served as a full scan on the next unchanged run).
func TestDeltaScanNotCachedAsFull(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", cacheDir)

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "main.go")
	if err := os.WriteFile(main, []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("main.go"); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@t", When: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	// Uncommitted edit so --base HEAD has a non-empty change set.
	if err := os.WriteFile(main, []byte("package main\n\nfunc main() { println(1) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(extra ...string) {
		out := filepath.Join(t.TempDir(), "o.json")
		root := NewRootCmd()
		args := append([]string{"scan", dir, "--no-deps", "--no-adapters", "-f", "json", "-o", out}, extra...)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("scan %v gagal: %v", extra, err)
		}
	}

	run("--base", "HEAD")
	if hasResultJSON(t, cacheDir) {
		t.Error("delta scan must not write result.json")
	}

	run() // full scan should persist a cacheable result
	if !hasResultJSON(t, cacheDir) {
		t.Error("full scan should write result.json")
	}
}

// hasResultJSON reports whether any session result.json exists under root.
func hasResultJSON(t *testing.T, root string) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "result.json" {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// TestScanJSONConfigSkip guards project-level issue-detector.json discovery and
// the `skip` alias: listed files/patterns must not be scanned.
func TestScanJSONConfigSkip(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())

	dir := t.TempDir()
	must := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Would otherwise raise a critical finding.
	must("keys.pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
	// JSON config discovered at root; `skip` is the alias for `ignore`.
	must("issue-detector.json", `{"skip": ["keys.pem"], "no_git": true}`)

	out := filepath.Join(t.TempDir(), "o.json")
	root := NewRootCmd()
	root.SetArgs([]string{"scan", dir, "--no-deps", "--no-adapters", "-f", "json", "-o", out})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep model.ScanResult
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.File, "keys.pem") {
			t.Errorf("file di-skip masih dilaporkan: %+v", f)
		}
	}
	// Only issue-detector.json itself remains enumerable.
	if rep.Summary.FilesEnumerated != 1 {
		t.Errorf("enumerated = %d, want 1 (keys.pem ter-skip)", rep.Summary.FilesEnumerated)
	}
}

// TestScanServesCachedResult verifies that scanning an unchanged project twice
// serves the stored result instead of re-running the detector, and that --force
// bypasses the cache read.
func TestScanServesCachedResult(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", cacheDir)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"),
		[]byte("const apiKey = 'sk-live-1234567890'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(extra ...string) (model.ScanResult, string) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "o.json")
		args := append([]string{"scan", dir, "--no-deps", "--no-adapters", "-f", "json", "-o", out}, extra...)
		cmd := NewRootCmd()
		cmd.SetArgs(args)

		old := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stderr = w
		execErr := cmd.Execute()
		w.Close()
		os.Stderr = old
		logs, _ := io.ReadAll(r)
		if execErr != nil {
			t.Fatalf("scan gagal: %v (stderr: %s)", execErr, logs)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var rep model.ScanResult
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatal(err)
		}
		return rep, string(logs)
	}

	first, logs1 := run()
	if strings.Contains(logs1, "memakai hasil cache") {
		t.Error("scan pertama tidak boleh dilayani dari cache")
	}
	resultPath := filepath.Join(cacheDir, "session_"+cache.SessionID(dir), "result.json")
	if _, err := os.Stat(resultPath); err != nil {
		t.Fatalf("result cache tidak ditulis: %v", err)
	}

	second, logs2 := run()
	if !strings.Contains(logs2, "memakai hasil cache") {
		t.Errorf("scan kedua harus dilayani cache; stderr=%s", logs2)
	}
	if second.ScanID == first.ScanID {
		t.Error("scan_id dari cache harus di-regenerate")
	}
	if len(second.Findings) != len(first.Findings) {
		t.Errorf("findings dari cache beda: %d vs %d", len(second.Findings), len(first.Findings))
	}

	forced, logs3 := run("--force")
	if strings.Contains(logs3, "memakai hasil cache") {
		t.Error("--force harus memaksa scan ulang, bukan cache")
	}
	if forced.ScanID == second.ScanID {
		t.Error("scan_id --force harus baru")
	}
}
