package web

import "github.com/rachmanzz/issue-detector/internal/rules"

type ruleSummary struct {
	ID         string   `json:"id"`
	Category   string   `json:"category"`
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	Languages  []string `json:"languages,omitempty"`
	Confidence float64  `json:"confidence"`
}

func ruleSummaries() []ruleSummary {
	reg := rules.NewRegistry()
	all := reg.All()
	out := make([]ruleSummary, 0, len(all))
	for _, r := range all {
		langs := make([]string, 0, len(r.Languages))
		for _, l := range r.Languages {
			langs = append(langs, string(l))
		}
		out = append(out, ruleSummary{
			ID: r.ID, Category: string(r.Category), Severity: string(r.Severity),
			Title: r.Title, Languages: langs, Confidence: r.Confidence,
		})
	}
	return out
}
