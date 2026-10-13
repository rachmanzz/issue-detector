package rules

import (
	"context"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/parser"
)

// ASTMatcher runs a tree-sitter query against the file's AST (attached by the
// parser). Rules using it are language-specific (the query is per-language).
// When the scanner has not pre-attached an AST (e.g. unit tests), the matcher
// parses one itself; when no grammar exists it matches nothing (line fallback).
type ASTMatcher struct {
	// Lang scopes the query to one language; matches nothing elsewhere.
	Lang  model.Language
	Query string
	// On converts a query match into a finding location. Return ok=false to
	// skip. When nil, the match's own line is used.
	On func(f *model.File, m model.ASTMatch) (model.Match, bool)
}

// Match implements Matcher.
func (a ASTMatcher) Match(_ context.Context, f *model.File) ([]model.Match, error) {
	if a.Lang != "" && f.Language != a.Lang {
		return nil, nil
	}
	syn := f.Syntax
	var own *parser.Syntax
	if syn == nil && parser.HasGrammar(f.Language) {
		s, err := parser.ParseSyntax(f)
		if err != nil {
			return nil, err
		}
		if s != nil {
			syn = s
			own = s
		}
	}
	if syn == nil {
		return nil, nil
	}
	if own != nil {
		defer own.Close()
	}

	hits, err := syn.FindAll(a.Query)
	if err != nil {
		return nil, err
	}
	var out []model.Match
	seen := map[int]bool{}
	for _, m := range hits {
		var mm model.Match
		ok := true
		if a.On != nil {
			mm, ok = a.On(f, m)
		} else {
			mm = model.Match{Line: m.Line, Snippet: strings.TrimSpace(f.Line(m.Line))}
		}
		if !ok || mm.Line < 1 || seen[mm.Line] {
			continue
		}
		seen[mm.Line] = true
		if mm.Snippet == "" {
			mm.Snippet = strings.TrimSpace(f.Line(mm.Line))
		}
		out = append(out, mm)
	}
	return out, nil
}
