package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func sarifSample() *model.ScanResult {
	return &model.ScanResult{
		SchemaVersion: "1",
		Tool:          model.ToolInfo{Name: "issue-detector", Version: "0.1.0"},
		ScanID:        "abc",
		Root:          "/tmp/proj",
		Findings: []model.Finding{
			{RuleID: "SECRET-001", Category: model.CategorySecrets, Severity: model.SeverityCritical,
				Title: "Hardcoded secret", Message: "cred", File: "a/b.go", Line: 7, Snippet: `x = "abc"`, FixHint: "use env"},
			{RuleID: "TODO-001", Category: model.CategoryTodo, Severity: model.SeverityInfo,
				Title: "TODO", Message: "todo", File: "c.go", Line: 2},
		},
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sarifSample()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs missing: %v", doc["runs"])
	}
	run := runs[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	first := results[0].(map[string]any)
	if first["ruleId"] != "SECRET-001" || first["level"] != "error" {
		t.Errorf("first result = %v", first)
	}
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	ruleList := driver["rules"].([]any)
	if len(ruleList) != 2 {
		t.Errorf("want 2 rule descriptors, got %d", len(ruleList))
	}
}
