package rules

import (
	"regexp"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// taintRule is a lightweight intraprocedural source→sink check (PRD §11 M3
// "dataflow ringan"). It tracks a variable assigned from a known input source
// and flags later use of it inside a sink call. Deliberately conservative:
//
//	ponytail: no aliasing/reassignment tracking or cross-function flows — a
//	value reassigned to a constant between source and sink is not modeled.
//	Upgrade to a real CFG/SSA pass (or tree-sitter query captures) at M6.
var taintRule = &Rule{
	Rule: model.Rule{
		ID:         "TAINT-001",
		Category:   model.CategorySecurity,
		Severity:   model.SeverityHigh,
		Title:      "Tainted input reaches a sink",
		Message:    "Nilai dari sumber input (HTTP/CLI/env) mengalir ke operasi sensitif (exec/SQL/log) tanpa sanitasi.",
		FixHint:    "Validasi/escape input, gunakan API parameterized, atau jangan lewatkan input mentah ke sink.",
		Languages:  nil,
		Confidence: 0.5,
	},
	Matcher: matchFunc(matchTaint),
}

var (
	sourceRes = []*regexp.Regexp{
		// Go
		regexp.MustCompile(`(\w+)\s*:?=\s*[\w.]*\.(FormValue|PostFormValue)\(`),
		regexp.MustCompile(`(\w+)\s*:?=\s*[\w.]*\.URL\.Query\(\)\.Get\(`),
		regexp.MustCompile(`(\w+)\s*:?=\s*os\.Args\b`),
		regexp.MustCompile(`(\w+)\s*:?=\s*io\.ReadAll\(`),
		// Python
		regexp.MustCompile(`(\w+)\s*=\s*request\.(args|form|values|json)\b`),
		regexp.MustCompile(`(\w+)\s*=\s*input\(`),
		// JavaScript
		regexp.MustCompile(`(\w+)\s*=\s*req\.(query|body|params)\b`),
		regexp.MustCompile(`(\w+)\s*=\s*(process\.argv|document\.location)\b`),
	}

	sinkRes = []*regexp.Regexp{
		regexp.MustCompile(`exec\.Command\w*\(`),
		regexp.MustCompile(`\.(Query|QueryContext|Exec|ExecContext)\(`),
		regexp.MustCompile(`\b(os\.system|subprocess\.(call|run|Popen)|eval|exec)\(`),
		regexp.MustCompile(`\bchild_process\.(exec|execSync)\(`),
		regexp.MustCompile(`(?i)\b(log|logger|logging)\.(info|warn|warning|error|debug)\w*\(`),
	}
)

func matchTaint(f *model.File) []model.Match {
	// First pass: variable -> line of first tainted assignment.
	tainted := map[string]int{}
	for i, line := range f.Lines {
		for _, re := range sourceRes {
			if m := re.FindStringSubmatch(line); m != nil {
				if _, ok := tainted[m[1]]; !ok {
					tainted[m[1]] = i + 1
				}
			}
		}
	}
	if len(tainted) == 0 {
		return nil
	}

	// Second pass: a sink that references a tainted variable.
	var matches []model.Match
	seen := map[string]bool{}
	for i, line := range f.Lines {
		isSink := false
		for _, re := range sinkRes {
			if re.MatchString(line) {
				isSink = true
				break
			}
		}
		if !isSink {
			continue
		}
		for v, srcLine := range tainted {
			if srcLine-1 == i { // the source line itself
				continue
			}
			if !containsIdent(line, v) {
				continue
			}
			key := f.RelPath + "\x00" + itoa(srcLine) + "\x00" + v
			if seen[key] {
				continue
			}
			seen[key] = true
			matches = append(matches, model.Match{
				Line:    srcLine,
				Snippet: strings.TrimSpace(f.Lines[srcLine-1]),
			})
			break
		}
		if len(matches) >= 3 {
			break
		}
	}
	return matches
}

// containsIdent reports whether line contains ident as a whole word.
func containsIdent(line, ident string) bool {
	idx := 0
	for {
		j := strings.Index(line[idx:], ident)
		if j < 0 {
			return false
		}
		j += idx
		before := byte(' ')
		if j > 0 {
			before = line[j-1]
		}
		after := byte(' ')
		if end := j + len(ident); end < len(line) {
			after = line[end]
		}
		if !isIdentByte(before) && !isIdentByte(after) {
			return true
		}
		idx = j + len(ident)
	}
}

func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// itoa is a tiny allocation-free int→string.
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
