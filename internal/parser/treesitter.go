// Tree-sitter AST support (PRD §5.1 "Parser"). Grammars are loaded lazily per
// language; languages without a grammar transparently fall back to the
// line-based engine. Queries are compiled once and cached (tree-sitter queries
// are immutable/read-only and safe to reuse across cursors and goroutines).
package parser

import (
	"fmt"
	"strings"
	"sync"

	ts "github.com/tree-sitter/go-tree-sitter"
	tsgo "github.com/tree-sitter/tree-sitter-go/bindings/go"
	tsjs "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tspy "github.com/tree-sitter/tree-sitter-python/bindings/go"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// grammarFor returns the tree-sitter language for l, or nil when unsupported.
func grammarFor(l model.Language) *ts.Language {
	switch l {
	case model.LanguageGo:
		return ts.NewLanguage(tsgo.Language())
	case model.LanguagePython:
		return ts.NewLanguage(tspy.Language())
	case model.LanguageJavaScript:
		return ts.NewLanguage(tsjs.Language())
	default:
		return nil
	}
}

// HasGrammar reports whether an AST grammar exists for l.
func HasGrammar(l model.Language) bool {
	return grammarFor(l) != nil
}

// Syntax is a parsed tree-sitter tree over the file's source.
type Syntax struct {
	lang model.Language
	tree *ts.Tree
	src  []byte
}

// Language implements model.Syntax.
func (s *Syntax) Language() model.Language { return s.lang }

// Close releases the underlying tree.
func (s *Syntax) Close() {
	if s != nil && s.tree != nil {
		s.tree.Close()
		s.tree = nil
	}
}

// ParseSyntax parses the file's lines. It returns (nil, nil) when no grammar is
// available (caller should use the line-based engine) or when parsing yields no
// tree. A tree containing syntax errors is still returned: partial ASTs are
// useful and rules treat them as best-effort.
func ParseSyntax(f *model.File) (*Syntax, error) {
	lang := grammarFor(f.Language)
	if lang == nil {
		return nil, nil
	}
	src := []byte(strings.Join(f.Lines, "\n"))

	p := ts.NewParser()
	defer p.Close()
	if err := p.SetLanguage(lang); err != nil {
		return nil, fmt.Errorf("set language %s: %w", f.Language, err)
	}
	tree := p.Parse(src, nil)
	if tree == nil {
		return nil, nil
	}
	return &Syntax{lang: f.Language, tree: tree, src: src}, nil
}

// AttachSyntax parses f and attaches the AST to f.Syntax. It is a no-op when the
// language has no grammar. Callers own the returned Syntax and must Close it.
func AttachSyntax(f *model.File) (*Syntax, error) {
	if f.Syntax != nil {
		if s, ok := f.Syntax.(*Syntax); ok {
			return s, nil
		}
	}
	syn, err := ParseSyntax(f)
	if err != nil || syn == nil {
		return syn, err
	}
	f.Syntax = syn
	return syn, nil
}

// queryCache caches compiled queries keyed by "<lang>\x00<query>".
var queryCache sync.Map // map[string]*ts.Query

func compileQuery(lang model.Language, query string) (*ts.Query, error) {
	key := string(lang) + "\x00" + query
	if v, ok := queryCache.Load(key); ok {
		return v.(*ts.Query), nil
	}
	l := grammarFor(lang)
	if l == nil {
		return nil, fmt.Errorf("no grammar for %s", lang)
	}
	q, err := ts.NewQuery(l, query)
	if err != nil {
		return nil, fmt.Errorf("compile query (%s): %v", lang, err)
	}
	queryCache.Store(key, q)
	return q, nil
}

// FindAll implements model.Syntax: it runs query and returns one ASTMatch per
// query match, capturing named nodes with their 1-based line numbers.
func (s *Syntax) FindAll(query string) ([]model.ASTMatch, error) {
	if s == nil || s.tree == nil {
		return nil, nil
	}
	q, err := compileQuery(s.lang, query)
	if err != nil {
		return nil, err
	}
	names := q.CaptureNames()

	cursor := ts.NewQueryCursor()
	defer cursor.Close()

	var out []model.ASTMatch
	it := cursor.Matches(q, s.tree.RootNode(), s.src)
	for m := it.Next(); m != nil; m = it.Next() {
		if len(m.Captures) == 0 {
			continue
		}
		caps := make([]model.ASTCapture, 0, len(m.Captures))
		line := int(m.Captures[0].Node.StartPosition().Row) + 1
		for _, c := range m.Captures {
			node := c.Node
			start := int(node.StartPosition().Row) + 1
			if start < line {
				line = start
			}
			caps = append(caps, model.ASTCapture{
				Name: names[c.Index],
				Text: string(s.src[node.StartByte():node.EndByte()]),
				Line: start,
			})
		}
		out = append(out, model.NewASTMatch(line, caps))
	}
	return out, nil
}
