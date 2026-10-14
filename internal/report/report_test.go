package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func sampleResult() *model.ScanResult {
	return &model.ScanResult{
		SchemaVersion: "1",
		Tool:          model.ToolInfo{Name: "issue-detector", Version: "0.1.0"},
		ScanID:        "abc-123",
		DurationMs:    42,
		Summary: model.Summary{
			FilesEnumerated: 2,
			FilesParsed:     2,
			BySeverity:      map[model.Severity]int{model.SeverityHigh: 1},
			Findings:        1,
		},
		Findings: []model.Finding{{
			RuleID: "GO-TEMP-001", Category: model.CategorySecurity, Severity: model.SeverityHigh,
			Title: "Insecure temporary file creation", File: "main.go", Line: 10,
			Snippet: "f, err := ioutil.TempFile", Confidence: 0.85, Source: model.SourceRule,
		}},
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{`"schema_version": "1"`, `"scan_id": "abc-123"`, `"rule_id": "GO-TEMP-001"`} {
		if !strings.Contains(s, want) {
			t.Errorf("json missing %s\n%s", want, s)
		}
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{"HIGH", "main.go:10", "Insecure temporary file creation"} {
		if !strings.Contains(s, want) {
			t.Errorf("text missing %q", want)
		}
	}
}

func TestWriteTextAISection(t *testing.T) {
	res := sampleResult()
	res.AISummary = "risiko sedang pada perubahan"
	res.Findings = append(res.Findings, model.Finding{
		RuleID: "AI-SECURITY", Category: model.CategorySecurity, Severity: model.SeverityHigh,
		Title: "Hardcoded secret", File: "a.go", Line: 3, Snippet: "key = \"x\"",
		Source: model.SourceAI,
	})
	var buf bytes.Buffer
	if err := WriteText(&buf, res); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{"AI summary: risiko sedang", "AI findings (1", "Hardcoded secret"} {
		if !strings.Contains(s, want) {
			t.Errorf("text missing %q\n%s", want, s)
		}
	}
}

func TestExitFor(t *testing.T) {
	res := sampleResult()

	if got := ExitFor(res, model.SeverityInfo, false); got != ExitOK {
		t.Errorf("fail-on none -> exit %d, want 0", got)
	}
	if got := ExitFor(res, model.SeverityHigh, false); got != ExitFindings {
		t.Errorf("fail-on high -> exit %d, want 1", got)
	}
	if got := ExitFor(res, model.SeverityCritical, false); got != ExitOK {
		t.Errorf("fail-on critical (only high present) -> exit %d, want 0", got)
	}

	clean := sampleResult()
	clean.Findings = nil
	if got := ExitFor(clean, model.SeverityLow, false); got != ExitOK {
		t.Errorf("no findings -> exit %d, want 0", got)
	}
}

// TestExitForAIGate verifies AI findings are advisory by default but gate the
// exit code when includeAI is set.
func TestExitForAIGate(t *testing.T) {
	res := sampleResult()
	res.Findings = []model.Finding{{
		Category: model.CategorySecurity, Severity: model.SeverityHigh,
		Title: "AI secret", File: "a.go", Line: 1, Source: model.SourceAI,
	}}
	if got := ExitFor(res, model.SeverityHigh, false); got != ExitOK {
		t.Errorf("AI advisory by default -> exit %d, want 0", got)
	}
	if got := ExitFor(res, model.SeverityHigh, true); got != ExitFindings {
		t.Errorf("--ai-gate high -> exit %d, want 1", got)
	}
}

func TestSortFindingsDeterministic(t *testing.T) {
	fs := []model.Finding{
		{File: "b.go", Line: 2, Severity: model.SeverityLow},
		{File: "a.go", Line: 5, Severity: model.SeverityHigh},
		{File: "a.go", Line: 1, Severity: model.SeverityHigh},
	}
	model.SortFindings(fs)
	got := []string{fs[0].File + ":" + itoa(fs[0].Line), fs[1].File + ":" + itoa(fs[1].Line), fs[2].File + ":" + itoa(fs[2].Line)}
	want := []string{"a.go:1", "a.go:5", "b.go:2"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sort order %v, want %v", got, want)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
