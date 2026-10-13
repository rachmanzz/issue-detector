// Package clone detects duplicated (cloned) code blocks across a scan using a
// token-window fingerprint (PRD §4.3 Deduplication / §11 M3). Exact token
// matches only — high precision, no near-miss approximation.
package clone

import (
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/fetcher"
	"github.com/rachmanzz/issue-detector/internal/model"
)

// DefaultMinTokens is the smallest block length considered a clone.
const DefaultMinTokens = 60

const maxCloneFindings = 20
const maxRead = 2 << 20

var supported = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".java": true, ".rb": true, ".rs": true,
}

type token struct {
	text string
	line int
}

var (
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentRe  = regexp.MustCompile(`(?m)//[^\n]*|#[^\n]*`)
	tokenRe        = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*|[0-9]+|"[^"]*"|'[^']*'|[{}()\[\];,.]|==|!=|<=|>=|&&|\|\||[+\-*/%=<>!&|^~?:]`)
)

// Detect returns DUP-001 findings for token-identical blocks appearing in two
// or more places. minTokens <= 0 uses DefaultMinTokens.
func Detect(entries []fetcher.Entry, minTokens int) []model.Finding {
	if minTokens <= 0 {
		minTokens = DefaultMinTokens
	}

	type spot struct {
		file string
		line int
	}
	windows := map[string][]spot{}

	for _, e := range entries {
		if !supported[strings.ToLower(path.Ext(e.RelPath))] || e.Size > maxRead {
			continue
		}
		toks, err := lexFile(e.Path)
		if err != nil || len(toks) < minTokens {
			continue
		}
		for i := 0; i+minTokens <= len(toks); i++ {
			key := windowKey(toks[i : i+minTokens])
			windows[key] = append(windows[key], spot{e.RelPath, toks[i].line})
		}
	}

	var out []model.Finding
	reported := map[string]bool{}
	lastLineInFile := map[string]int{}
	for _, spots := range windows {
		if len(spots) < 2 {
			continue
		}
		// Deterministic order; skip the first occurrence (the "original").
		for _, s := range spots[1:] {
			if reported[s.file+"\x00"+itoa(s.line)] {
				continue
			}
			// Fuse overlapping windows in the same file: report one region.
			if prev := lastLineInFile[s.file]; prev > 0 && s.line-prev < fuseLines {
				continue
			}
			lastLineInFile[s.file] = s.line
			reported[s.file+"\x00"+itoa(s.line)] = true
			out = append(out, model.Finding{
				RuleID: "DUP-001", Category: model.CategoryQuality, Severity: model.SeverityLow,
				Title:   "Duplicated code block",
				Message: "Blok kode identik muncul di lebih dari satu tempat — kandidat ekstraksi fungsi.",
				FixHint: "Ekstrak ke fungsi/modul bersama; kurangi duplikasi.",
				File:    s.file, Line: s.line, Source: model.SourceRule, Confidence: 0.5,
			})
			if len(out) >= maxCloneFindings {
				return out
			}
		}
	}
	return out
}

// fuseLines merges windows that start within a few lines of each other, so a
// repeated block is reported once instead of once per offset (roast v8).
const fuseLines = 12

// lexFile strips comments and returns a normalized token stream with lines.
func lexFile(p string) ([]token, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	src := string(data)
	src = blockCommentRe.ReplaceAllString(src, " ")
	src = lineCommentRe.ReplaceAllString(src, " ")

	var toks []token
	line := 1
	last := 0
	for _, loc := range tokenRe.FindAllStringIndex(src, -1) {
		line += strings.Count(src[last:loc[0]], "\n")
		last = loc[0]
		toks = append(toks, token{text: src[loc[0]:loc[1]], line: line})
	}
	return toks, nil
}

func windowKey(toks []token) string {
	var b strings.Builder
	for i, t := range toks {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(t.text)
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
