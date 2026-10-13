// Package score ranks findings with an explainable priority_score (PRD §11 M7).
// The score is deterministic and derived only from the finding itself so it can
// be reproduced and audited; ScoreReason spells out each contributing factor.
package score

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// categoryBonus weights categories by exploitability/urgency.
var categoryBonus = map[model.Category]float64{
	model.CategorySecrets:    10,
	model.CategorySecurity:   8,
	model.CategoryDependency: 6,
	model.CategoryBug:        5,
	model.CategoryPosture:    4,
	model.CategoryGit:        3,
	model.CategoryQuality:    2,
	model.CategoryTodo:       1,
}

// Score computes a 0–100 priority and a human-readable reason.
func Score(f model.Finding) (float64, string) {
	sev := float64(model.SeverityWeight[f.Severity]) / 4 * 60 // 0–60
	conf := f.Confidence * 15                                 // 0–15
	cat := categoryBonus[f.Category]                          // 0–10
	inDiff := 0.0
	if f.InDiff {
		inDiff = 10
	}
	refs := 0.0
	if len(f.References) > 0 {
		refs = 5
	}

	raw := sev + conf + cat + inDiff + refs
	if raw > 100 {
		raw = 100
	}

	reasons := []string{
		fmt.Sprintf("severity=%s(+%.0f)", f.Severity, sev),
		fmt.Sprintf("confidence=%.2f(+%.0f)", f.Confidence, conf),
		fmt.Sprintf("category=%s(+%.0f)", f.Category, cat),
	}
	if inDiff > 0 {
		reasons = append(reasons, "in_diff(+10)")
	}
	if refs > 0 {
		reasons = append(reasons, "has_references(+5)")
	}
	return round1(raw), strings.Join(reasons, " ")
}

// Apply computes and stores the score for every finding, then keeps the
// result sorted by priority (highest first) with stable tie-breaks.
func Apply(findings []model.Finding) {
	for i := range findings {
		s, r := Score(findings[i])
		findings[i].PriorityScore = s
		findings[i].ScoreReason = r
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].PriorityScore != findings[j].PriorityScore {
			return findings[i].PriorityScore > findings[j].PriorityScore
		}
		return false
	})
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
