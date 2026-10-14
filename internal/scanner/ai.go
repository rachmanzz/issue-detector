package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/rachmanzz/issue-detector/internal/fetcher"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/parser"
	"github.com/rachmanzz/issue-detector/internal/score"
	"github.com/rachmanzz/issue-detector/internal/version"
)

// scanAI runs AI-detector mode: gather the changed (or, with no delta, all)
// source files, hand their full content to the Detector, and return its findings
// as the sole result. No rule engine, git/posture/clone/deps analysis (PRD §3.2).
func (s *Scanner) scanAI(ctx context.Context, root string, entries []fetcher.Entry, scanID string, start time.Time) (*model.ScanResult, error) {
	if s.opts.Detector == nil {
		return nil, errors.New("AI-only mode requires a detector")
	}
	cfg := s.opts.Config

	changed := map[string]bool{}
	if s.opts.Delta != nil {
		for _, p := range s.opts.Delta.Paths() {
			changed[filepath.ToSlash(p)] = true
		}
	}

	maxFiles := cfg.AI.MaxFiles
	if maxFiles < 1 {
		maxFiles = 200
	}
	files := make([]model.AIFile, 0, len(entries))
	for _, e := range entries {
		rel := filepath.ToSlash(e.RelPath)
		if s.opts.Delta != nil && !changed[rel] {
			continue
		}
		f, err := parser.ReadFile(e.Path, e.RelPath, e.Size, cfg.MaxFileSize)
		if err != nil || f.Skipped || f.Binary {
			continue
		}
		content := strings.Join(f.Lines, "\n")
		af := model.AIFile{
			RelPath:  rel,
			Content:  content,
			Language: f.Language,
			ID:       rel + "#" + shortHash(content),
		}
		switch {
		case s.opts.Delta == nil || s.opts.Delta.New[rel]:
			af.Full = true // whole file (full scan or new relative to base)
		default:
			for _, r := range s.opts.Delta.Files[rel] {
				af.Ranges = append(af.Ranges, model.LineRange{Start: r.Start, End: r.End})
			}
			if len(af.Ranges) == 0 {
				af.Full = true // changed path with no recorded ranges
			}
		}
		files = append(files, af)
		if len(files) >= maxFiles {
			break
		}
	}

	s.log.Info("ai-only scan", "files", len(files), "changed", len(changed), "max_files", maxFiles)
	findings, summary, err := s.opts.Detector.Detect(ctx, files)
	if err != nil {
		// A failed chunk means the file set was not fully reviewed; mark the
		// result partial so the ledger is not advanced (the next run retries).
		s.log.Warn("ai detector error", "err", err)
	}
	// Cosmetic findings (the "info" floor — typos/style/nits) are dropped so the
	// AI-only report stays assertive and doesn't surface noise (PRD §3.2).
	findings = dropCosmetic(findings)
	// Delta scans are diff-only (diff + uncommitted, PRD §3.4): keep only
	// findings whose own line is inside the change set, and mark them InDiff.
	// The model may flag unchanged/context lines or guess; those are not part of
	// the diff and must not be reported (no false positives outside the change).
	if s.opts.Delta != nil {
		kept := findings[:0]
		for _, f := range findings {
			if s.opts.Delta.Contains(filepath.ToSlash(f.File), f.Line) {
				f.InDiff = true
				kept = append(kept, f)
			}
		}
		findings = kept
	}
	findings = dedup(findings)
	model.SortFindings(findings)
	score.Apply(findings, cfg.ScoreWeights)

	sum := model.Summary{FilesEnumerated: len(files), Findings: len(findings)}
	sum.BySeverity = map[model.Severity]int{}
	for _, f := range findings {
		sum.BySeverity[f.Severity]++
	}

	res := &model.ScanResult{
		SchemaVersion: version.SchemaVersion,
		Tool:          model.ToolInfo{Name: version.ToolName, Version: version.Version},
		ScanID:        scanID,
		Root:          root,
		DurationMs:    time.Since(start).Milliseconds(),
		Summary:       sum,
		Findings:      findings,
		AISummary:     summary,
	}
	if err != nil {
		res.Status = model.StatusPartial
		res.ScanErrors = append(res.ScanErrors, err.Error())
	}
	return res, nil
}

// dropCosmetic removes AI findings at the cosmetic floor (severity "info"), so
// style/naming/typo nitpicks never reach the report.
func dropCosmetic(fs []model.Finding) []model.Finding {
	out := fs[:0]
	for _, f := range fs {
		if f.Severity != model.SeverityInfo {
			out = append(out, f)
		}
	}
	return out
}

// shortHash is a 12-char content handle used to build AI file ids; including the
// content hash means a requested "full" repush can never serve a stale revision.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
