package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/delta"
	"github.com/rachmanzz/issue-detector/internal/model"
)

type stubDetector struct {
	got      []string
	findings []model.Finding
	summary  string
	err      error
}

func (s *stubDetector) Detect(_ context.Context, files []model.AIFile) ([]model.Finding, string, error) {
	for _, f := range files {
		s.got = append(s.got, f.RelPath)
	}
	return s.findings, s.summary, s.err
}

func TestScanAIOnly(t *testing.T) {
	dir := writeFixture(t)
	cfg := config.Default()
	cfg.NoGit = true

	det := &stubDetector{
		findings: []model.Finding{{
			RuleID: "AI-SECURITY", Category: model.CategorySecurity, Severity: model.SeverityHigh,
			Title: "Rahasia ter-hardcode", File: "main.go", Line: 1, Source: model.SourceAI,
		}},
		summary: "ringkas perubahan",
	}
	res, err := Scan(context.Background(), Options{
		Root: dir, Config: cfg, AIOnly: true, Detector: det,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if res.AISummary != det.summary {
		t.Errorf("ai summary = %q", res.AISummary)
	}
	if len(res.Findings) != 1 || res.Findings[0].Source != model.SourceAI {
		t.Fatalf("want 1 AI finding, got %+v", res.Findings)
	}
	seen := map[string]bool{}
	for _, p := range det.got {
		seen[p] = true
	}
	if !seen["main.go"] {
		t.Errorf("detector did not receive main.go; got %v", det.got)
	}
	if len(det.got) == 0 {
		t.Fatal("detector received no files")
	}
}

func TestScanAIOnlyDeltaFilter(t *testing.T) {
	dir := writeFixture(t)
	cfg := config.Default()
	cfg.NoGit = true
	det := &stubDetector{}

	set := &delta.Set{Files: map[string][]delta.Range{"main.go": {{Start: 1, End: 1}}}}
	_, err := Scan(context.Background(), Options{
		Root: dir, Config: cfg, AIOnly: true, Detector: det, Delta: set,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(det.got) != 1 || det.got[0] != "main.go" {
		t.Fatalf("delta filter should pass only main.go, got %v", det.got)
	}
}

// TestScanAIOnlyKeepsOnlyDiffFindings guards the diff-only rule: in a delta scan
// a finding whose line is inside the change set is kept and marked InDiff, while
// one on an unchanged/context line is dropped (no false positives off the diff).
func TestScanAIOnlyKeepsOnlyDiffFindings(t *testing.T) {
	dir := writeFixture(t)
	cfg := config.Default()
	cfg.NoGit = true
	det := &stubDetector{findings: []model.Finding{
		{Category: model.CategoryBug, Severity: model.SeverityHigh, Title: "changed", File: "main.go", Line: 1, Source: model.SourceAI},
		{Category: model.CategoryBug, Severity: model.SeverityLow, Title: "context", File: "main.go", Line: 5, Source: model.SourceAI},
	}}
	set := &delta.Set{Files: map[string][]delta.Range{"main.go": {{Start: 1, End: 1}}}}
	res, err := Scan(context.Background(), Options{
		Root: dir, Config: cfg, AIOnly: true, Detector: det, Delta: set,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("diff scan must keep only in-diff findings, got %d: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].Title != "changed" || !res.Findings[0].InDiff {
		t.Errorf("want kept 'changed' with InDiff=true, got %+v", res.Findings[0])
	}
}

// TestScanAIOnlyDropsCosmetic verifies info-floor (cosmetic) findings are
// dropped so the AI-only report stays assertive.
func TestScanAIOnlyDropsCosmetic(t *testing.T) {
	dir := writeFixture(t)
	cfg := config.Default()
	cfg.NoGit = true
	det := &stubDetector{findings: []model.Finding{
		{Category: model.CategoryBug, Severity: model.SeverityLow, Title: "real", File: "main.go", Line: 1, Source: model.SourceAI},
		{Category: model.CategoryQuality, Severity: model.SeverityInfo, Title: "typo nit", File: "main.go", Line: 1, Source: model.SourceAI},
	}}
	res, err := Scan(context.Background(), Options{Root: dir, Config: cfg, AIOnly: true, Detector: det})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Title != "real" {
		t.Fatalf("cosmetic finding must be dropped, got %+v", res.Findings)
	}
}

// TestScanAIOnlyIncompleteOnDetectorError guards that a detector failure marks
// the result Incomplete (so the caller does not advance the session ledger).
func TestScanAIOnlyIncompleteOnDetectorError(t *testing.T) {
	dir := writeFixture(t)
	cfg := config.Default()
	cfg.NoGit = true
	det := &stubDetector{err: errors.New("boom")}
	res, err := Scan(context.Background(), Options{Root: dir, Config: cfg, AIOnly: true, Detector: det})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete {
		t.Errorf("detector error must set Incomplete=true")
	}
}

func TestScanAIOnlyRequiresDetector(t *testing.T) {
	dir := writeFixture(t)
	cfg := config.Default()
	cfg.NoGit = true
	if _, err := Scan(context.Background(), Options{Root: dir, Config: cfg, AIOnly: true}); err == nil {
		t.Fatal("expected error when AIOnly without detector")
	}
}
