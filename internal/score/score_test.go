package score

import (
	"strings"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestScoreOrdersBySeverityAndContext(t *testing.T) {
	sec := model.Finding{RuleID: "SECRET-001", Category: model.CategorySecrets,
		Severity: model.SeverityCritical, Confidence: 0.9, InDiff: true}
	todo := model.Finding{RuleID: "TODO-001", Category: model.CategoryTodo,
		Severity: model.SeverityInfo, Confidence: 0.9}

	sSec, rSec := Score(sec)
	sTodo, _ := Score(todo)
	if sSec <= sTodo {
		t.Errorf("critical secret (%.1f) should outrank info todo (%.1f)", sSec, sTodo)
	}
	if sSec > 100 {
		t.Errorf("score must be capped at 100, got %.1f", sSec)
	}
	for _, want := range []string{"severity=", "confidence=", "category=", "in_diff"} {
		if !strings.Contains(rSec, want) {
			t.Errorf("reason missing %q: %s", want, rSec)
		}
	}
}

func TestApplySortsByPriority(t *testing.T) {
	fs := []model.Finding{
		{RuleID: "TODO-001", Category: model.CategoryTodo, Severity: model.SeverityInfo, Confidence: 0.5},
		{RuleID: "SEC-INJ-001", Category: model.CategorySecurity, Severity: model.SeverityHigh, Confidence: 0.8},
	}
	Apply(fs)
	if fs[0].RuleID != "SEC-INJ-001" {
		t.Errorf("expected high security first, got %s", fs[0].RuleID)
	}
	if fs[0].PriorityScore == 0 || fs[0].ScoreReason == "" {
		t.Errorf("score not populated: %+v", fs[0])
	}
}
