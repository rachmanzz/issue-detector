package scanner

import (
	"fmt"
	"sync"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// aggregator accumulates per-file results from concurrent handlers.
// Findings are deduplicated (rule,file,line) which also makes queue handler
// retries safe against double counting.
type aggregator struct {
	mu        sync.Mutex
	findings  []model.Finding
	seen      map[string]bool
	parsed    int
	skipped   int
	errs      int
	completed int
}

func newAggregator() *aggregator {
	return &aggregator{seen: make(map[string]bool)}
}

// commit applies one file's results. Caller must have settled the message.
func (a *aggregator) commit(parsed, skipped, errs int, findings []model.Finding) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.parsed += parsed
	a.skipped += skipped
	a.errs += errs
	a.completed++
	for _, f := range findings {
		key := fmt.Sprintf("%s\x00%s\x00%d", f.RuleID, f.File, f.Line)
		if a.seen[key] {
			continue
		}
		a.seen[key] = true
		a.findings = append(a.findings, f)
	}
}

// snapshot returns a stable copy of current findings (sorted).
func (a *aggregator) snapshot() []model.Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]model.Finding, len(a.findings))
	copy(out, a.findings)
	model.SortFindings(out)
	return out
}

// dedup removes findings sharing (rule, file, line), preserving order.
func dedup(in []model.Finding) []model.Finding {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, f := range in {
		key := fmt.Sprintf("%s\x00%s\x00%d", f.RuleID, f.File, f.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// progress reports how many files have settled.
func (a *aggregator) progress() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.completed
}

func (a *aggregator) summary() model.Summary {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := model.Summary{
		FilesParsed:  a.parsed,
		FilesSkipped: a.skipped,
		Errors:       a.errs,
		Findings:     len(a.findings),
		BySeverity:   make(map[model.Severity]int),
	}
	for _, f := range a.findings {
		s.BySeverity[f.Severity]++
	}
	return s
}
