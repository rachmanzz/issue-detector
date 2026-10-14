package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/model"
)

func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	files := map[string]string{
		"main.go": `package main

import "io/ioutil"

func temp() string {
	f, _ := ioutil.TempFile("", "app") // GO-TEMP-001
	return f.Name()
}
`,
		"app.js":           "console.log('debug');\n",
		"secret.env":       "DB_PASSWORD = \"hunter2-hunter2-hunter2\"\n",
		"keys/id_rsa.pem":  "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
		"generated/out.go": "// harus di-ignore\n",
		".gitignore":       "generated/\n",
	}
	for path, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hasFinding(t *testing.T, fs []model.Finding, ruleID, file string) bool {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == ruleID && f.File == file {
			return true
		}
	}
	return false
}

func TestScannerIntegration(t *testing.T) {
	dir := writeFixture(t)
	cfg := config.Default()
	res, err := Scan(context.Background(), Options{Root: dir, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}

	if res.SchemaVersion != "1" {
		t.Errorf("schema_version = %q", res.SchemaVersion)
	}
	if res.Summary.FilesEnumerated != 5 {
		t.Errorf("files enumerated = %d, want 5 (generated/ harus ignore)", res.Summary.FilesEnumerated)
	}
	if !hasFinding(t, res.Findings, "GO-TEMP-001", "main.go") {
		t.Error("GO-TEMP-001 missing on main.go")
	}
	if !hasFinding(t, res.Findings, "SECRET-002", "keys/id_rsa.pem") {
		t.Error("SECRET-002 missing on keys/id_rsa.pem")
	}
	if !hasFinding(t, res.Findings, "SECRET-001", "secret.env") {
		t.Error("SECRET-001 missing on secret.env")
	}
	if !hasFinding(t, res.Findings, "DBG-001", "app.js") {
		t.Error("DBG-001 missing on app.js")
	}

	// Deterministic ordering across runs.
	expected := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		expected = append(expected, f.RuleID+"|"+f.File+"|"+itoa(f.Line))
	}
	res2, err := Scan(context.Background(), Options{Root: dir, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(res2.Findings))
	for _, f := range res2.Findings {
		got = append(got, f.RuleID+"|"+f.File+"|"+itoa(f.Line))
	}
	if len(expected) != len(got) {
		t.Fatalf("finding counts differ between runs: %d vs %d", len(expected), len(got))
	}
	for i := range expected {
		if expected[i] != got[i] {
			t.Errorf("order drift at %d: %s vs %s", i, expected[i], got[i])
		}
	}
}

func TestScannerFilterSeverityMin(t *testing.T) {
	dir := writeFixture(t)
	cfg := config.Default()
	res, err := Scan(context.Background(), Options{
		Root:   dir,
		Config: cfg,
		Filter: model.Filter{SeverityMin: model.SeverityHigh},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if model.SeverityWeight[f.Severity] < model.SeverityWeight[model.SeverityHigh] {
			t.Errorf("finding di bawah severity-min: %+v", f)
		}
	}
}

// BenchmarkScan measures end-to-end pipeline throughput over a synthetic Go
// tree (PRD §10: target >100k LOC under 30s).
func BenchmarkScan(b *testing.B) {
	dir := b.TempDir()
	const files = 200
	body := `package p

import "io/ioutil"

func f%d() {
	f, _ := ioutil.TempFile("", "x")
	_ = f
}
`
	for i := 0; i < files; i++ {
		src := fmt.Sprintf(body, i) + strings.Repeat("// filler line to grow the file\n", 50)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.go", i)), []byte(src), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.NoGit = true
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Scan(context.Background(), Options{Root: dir, Config: cfg}); err != nil {
			b.Fatal(err)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestScanConcurrent guards roast v2/v28: two scans run truly in parallel
// (each with its own gosuite engine + queue) and stay independent — no global
// state, no serialization. Run under -race in CI.
func TestScanConcurrent(t *testing.T) {
	dirA := writeFixture(t)
	dirB := writeFixture(t)

	var wg sync.WaitGroup
	results := make([]*model.ScanResult, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			root := dirA
			if i == 1 {
				root = dirB
			}
			results[i], errs[i] = Scan(context.Background(), Options{Root: root, Config: config.Default()})
		}(i)
	}
	wg.Wait()

	for i := 0; i < 2; i++ {
		if errs[i] != nil {
			t.Fatalf("scan %d gagal: %v", i, errs[i])
		}
		if results[i].Summary.FilesEnumerated != 5 {
			t.Errorf("scan %d files = %d, want 5", i, results[i].Summary.FilesEnumerated)
		}
	}
}

// TestCompletionTrackerDoneAfterCommit guards the ordering that fixes a
// dropped-finding race: the commit callback must run before done is closed,
// otherwise Wait returns and a snapshot can miss the settling file's findings.
func TestCompletionTrackerDoneAfterCommit(t *testing.T) {
	tr := newCompletionTracker(1)
	var closedInsideCommit bool
	tr.complete("file", func() {
		select {
		case <-tr.done:
			closedInsideCommit = true
		default:
		}
	})
	if closedInsideCommit {
		t.Fatal("done must not be closed before the commit callback runs")
	}
	if err := tr.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}
