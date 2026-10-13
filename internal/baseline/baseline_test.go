package baseline

import (
	"path/filepath"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func res(rule, file, snippet string, line int) *model.ScanResult {
	return &model.ScanResult{
		Findings: []model.Finding{{
			RuleID: rule, File: file, Snippet: snippet, Line: line,
			Severity: model.SeverityHigh, Category: model.CategorySecurity,
		}},
		Summary: model.Summary{BySeverity: map[model.Severity]int{model.SeverityHigh: 1}},
	}
}

func TestSaveLoadFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := Save(path, res("SEC-INJ-001", "a.go", `exec.Command("sh","-c",x)`, 10)); err != nil {
		t.Fatal(err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 {
		t.Fatalf("want 1 fingerprint, got %d", len(set))
	}
	// Same finding at a different line still matches (line-independent).
	r2 := res("SEC-INJ-001", "a.go", `exec.Command("sh","-c",x)`, 999)
	if n := set.Filter(r2); n != 1 || len(r2.Findings) != 0 {
		t.Errorf("expected baseline to suppress, removed=%d remaining=%d", n, len(r2.Findings))
	}
	if r2.Summary.Findings != 0 || r2.Summary.Baselined != 1 {
		t.Errorf("summary not updated: %+v", r2.Summary)
	}
}

func TestLoadMissing(t *testing.T) {
	set, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing baseline should not error: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("want empty set, got %d", len(set))
	}
}

func TestFingerprintDistinguishes(t *testing.T) {
	a := Fingerprint(model.Finding{RuleID: "R", File: "a.go", Snippet: "x"})
	b := Fingerprint(model.Finding{RuleID: "R", File: "b.go", Snippet: "x"})
	if a == b {
		t.Error("different files must have different fingerprints")
	}
}
