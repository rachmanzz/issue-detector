// Package report renders ScanResult into text or JSON and derives exit codes
// (PRD §9: stable schema + versioned JSON contract; §7 --fail-on gate).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// Exit codes (PRD §9 agent contract):
//
//	0 clean (or nothing above the gate)
//	1 findings above the fail-on threshold
//	2 scan ran with errors (partial results)
const (
	ExitOK        = 0
	ExitFindings  = 1
	ExitScanError = 2
)

// WriteJSON streams the report as a single JSON document.
func WriteJSON(w io.Writer, res *model.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// WriteText renders the human-readable report (PRD §9 example shape).
func WriteText(w io.Writer, res *model.ScanResult) error {
	var b strings.Builder

	fmt.Fprintf(&b, "%s v%s (scan %s)\n", capitalize(res.Tool.Name), res.Tool.Version, shortID(res.ScanID))
	b.WriteString(strings.Repeat("─", 56) + "\n")

	if len(res.Findings) == 0 {
		b.WriteString("\nNo findings.\n")
	}

	for _, f := range res.Findings {
		fmt.Fprintf(&b, "\n%s  %-8s  %s:%-4d  %s\n",
			strings.ToUpper(string(f.Severity)), f.Category, f.File, f.Line, f.Title)
		fmt.Fprintf(&b, "       %s\n", clip(f.Snippet, 80))
		fmt.Fprintf(&b, "       confidence=%.2f  source=%s  rule=%s\n", f.Confidence, f.Source, f.RuleID)
		if f.FixHint != "" {
			fmt.Fprintf(&b, "       fix: %s\n", f.FixHint)
		}
	}

	sum := res.Summary
	b.WriteString("\n" + strings.Repeat("─", 56) + "\n")
	fmt.Fprintf(&b, "Files: %d scanned, %d parsed, %d skipped, %d errors\n",
		sum.FilesEnumerated, sum.FilesParsed, sum.FilesSkipped, sum.Errors)
	fmt.Fprintf(&b, "Findings: %d   ", sum.Findings)
	sevs := []model.Severity{
		model.SeverityCritical, model.SeverityHigh, model.SeverityMedium,
		model.SeverityLow, model.SeverityInfo,
	}
	parts := make([]string, 0, len(sevs))
	for _, s := range sevs {
		if n := sum.BySeverity[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", string(s), n))
		}
	}
	fmt.Fprintf(&b, "(%s)\n", strings.Join(parts, ", "))
	fmt.Fprintf(&b, "Duration: %d ms\n", res.DurationMs)

	_, err := io.WriteString(w, b.String())
	return err
}

// ExitFor computes the process exit code from a report per the fail-on gate.
// failOn is one of: none, low, medium, high, critical.
func ExitFor(res *model.ScanResult, failOn model.Severity) int {
	if failOn == "" || failOn == model.SeverityInfo {
		return ExitOK
	}
	threshold := model.SeverityWeight[failOn]
	for _, f := range res.Findings {
		// AI-sourced findings are advisory and excluded from the gate (PRD §3.5).
		if f.Source == model.SourceAI {
			continue
		}
		if model.SeverityWeight[f.Severity] >= threshold {
			return ExitFindings
		}
	}
	return ExitOK
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
