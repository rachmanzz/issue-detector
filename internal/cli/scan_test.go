package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// TestScanHonorsYAMLConfig guards the regression where YAML keys
// (severity_min/no_git/…) were clobbered by flag defaults.
func TestScanHonorsYAMLConfig(t *testing.T) {
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
