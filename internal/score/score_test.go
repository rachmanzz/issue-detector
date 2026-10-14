package score

import (
	"strings"
	"sync"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestScoreOrdersBySeverityAndContext(t *testing.T) {
	sec := model.Finding{RuleID: "SECRET-001", Category: model.CategorySecrets,
		Severity: model.SeverityCritical, Confidence: 0.9, InDiff: true}
	todo := model.Finding{RuleID: "TODO-001", Category: model.CategoryTodo,
		Severity: model.SeverityInfo, Confidence: 0.9}

	sSec, rSec := Score(sec, Weights{})
	sTodo, _ := Score(todo, Weights{})
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
	Apply(fs, Weights{})
	if fs[0].RuleID != "SEC-INJ-001" {
		t.Errorf("expected high security first, got %s", fs[0].RuleID)
	}
	if fs[0].PriorityScore == 0 || fs[0].ScoreReason == "" {
		t.Errorf("score not populated: %+v", fs[0])
	}
}

// TestApplyConcurrentRaceFree guards that scoring no longer mutates package
// state: concurrent Apply with different weights must be race-free (run with
// -race in CI) and each call must use its own weights.
func TestApplyConcurrentRaceFree(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := Weights{Severity: float64(10 + i)}
			fs := []model.Finding{{RuleID: "X", Category: model.CategoryBug,
				Severity: model.SeverityHigh, Confidence: 0.5}}
			Apply(fs, w)
			if fs[0].PriorityScore == 0 {
				t.Errorf("score not set")
			}
		}(i)
	}
	wg.Wait()
}
