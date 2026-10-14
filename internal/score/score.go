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
func defaultCategoryBonus() map[model.Category]float64 {
	return map[model.Category]float64{
		model.CategorySecrets:    10,
		model.CategorySecurity:   8,
		model.CategoryDependency: 6,
		model.CategoryBug:        5,
		model.CategoryPosture:    4,
		model.CategoryGit:        3,
		model.CategoryQuality:    2,
		model.CategoryTodo:       1,
	}
}

// Weights are the tuneable priority-score coefficients (roast v9: no longer
// undocumented constants). Zero fields fall back to the defaults.
type Weights struct {
	Severity   float64                    `yaml:"severity" json:"severity"`
	Confidence float64                    `yaml:"confidence" json:"confidence"`
	Category   map[model.Category]float64 `yaml:"category" json:"category"`
	InDiff     float64                    `yaml:"in_diff" json:"in_diff"`
	References float64                    `yaml:"references" json:"references"`
}

// DefaultWeights returns the recommended coefficients.
func DefaultWeights() Weights {
	return Weights{
		Severity: 60, Confidence: 15, Category: defaultCategoryBonus(),
		InDiff: 10, References: 5,
	}
}

// Resolve returns w with zero fields filled from the defaults, so callers may
// pass a partial config. It is pure: no package state is mutated, so scoring is
// safe under concurrent scans (roast v27).
func Resolve(w Weights) Weights {
	d := DefaultWeights()
	if w.Severity != 0 {
		d.Severity = w.Severity
	}
	if w.Confidence != 0 {
		d.Confidence = w.Confidence
	}
	if w.InDiff != 0 {
		d.InDiff = w.InDiff
	}
	if w.References != 0 {
		d.References = w.References
	}
	for k, v := range w.Category {
		if v != 0 {
			d.Category[k] = v
		}
	}
	return d
}

// Score computes a 0–100 priority and a human-readable reason using w (zero
// fields fall back to defaults).
func Score(f model.Finding, w Weights) (float64, string) {
	return scoreWith(f, Resolve(w))
}

// scoreWith scores against already-resolved weights.
func scoreWith(f model.Finding, w Weights) (float64, string) {
	sev := float64(model.SeverityWeight[f.Severity]) / 4 * w.Severity
	conf := f.Confidence * w.Confidence
	cat := w.Category[f.Category]
	inDiff := 0.0
	if f.InDiff {
		inDiff = w.InDiff
	}
	refs := 0.0
	if len(f.References) > 0 {
		refs = w.References
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
		reasons = append(reasons, fmt.Sprintf("in_diff(+%.0f)", inDiff))
	}
	if refs > 0 {
		reasons = append(reasons, fmt.Sprintf("references(+%.0f)", refs))
	}
	return round1(raw), strings.Join(reasons, " ")
}

// Apply computes and stores the score for every finding using w (zero fields
// fall back to defaults), then keeps the result sorted by priority (highest
// first) with stable tie-breaks.
func Apply(findings []model.Finding, w Weights) {
	rw := Resolve(w)
	for i := range findings {
		s, r := scoreWith(findings[i], rw)
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
