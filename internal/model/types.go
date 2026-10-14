// Package model defines the core domain types shared across the scanner,
// rules, parsers, and reporters (PRD §9).
package model

import (
	"sort"
	"strings"
)

// Category groups detection rules (PRD §4).
type Category string

const (
	CategorySecurity   Category = "security"
	CategoryQuality    Category = "quality"
	CategoryBug        Category = "bug"
	CategoryGit        Category = "git"
	CategorySecrets    Category = "secrets"
	CategoryTodo       Category = "todo"
	CategoryDependency Category = "dependency"
	CategoryPosture    Category = "posture"
)

// AllCategories is the canonical ordered list of categories.
var AllCategories = []Category{
	CategorySecurity,
	CategoryQuality,
	CategoryBug,
	CategoryGit,
	CategorySecrets,
	CategoryTodo,
	CategoryDependency,
	CategoryPosture,
}

// Severity levels, ordered from least to most severe.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityWeight maps a severity to a comparable integer (higher = worse).
var SeverityWeight = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Source of a finding (PRD §9: rule | adapter | ai | plugin).
type Source string

const (
	SourceRule    Source = "rule"
	SourceAdapter Source = "adapter"
	SourceAI      Source = "ai"
	SourcePlugin  Source = "plugin"
)

// Language identified for a scanned file.
type Language string

const (
	LanguageGo         Language = "go"
	LanguagePython     Language = "python"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
	LanguageUnknown    Language = "unknown"
)

// File represents one source file being scanned.
type File struct {
	Path       string // absolute path on disk
	RelPath    string // path relative to the scan root
	Size       int64
	Language   Language
	Lines      []string // 0-indexed; display line numbers are 1-based
	Binary     bool
	Skipped    bool
	SkipReason string

	// Syntax is the optional parsed AST (tree-sitter), attached by the parser
	// before rules run. Nil when the language has no grammar (line fallback).
	Syntax Syntax
}

// ASTCapture is a single named capture from a tree-sitter query match.
type ASTCapture struct {
	Name string
	Text string
	Line int // 1-based
}

// ASTMatch is one tree-sitter query match, exposing captures by name.
type ASTMatch struct {
	Ordered []ASTCapture
	byName  map[string]ASTCapture
	Line    int // 1-based line of the match start
}

// Get returns a capture by name.
func (m ASTMatch) Get(name string) (ASTCapture, bool) {
	c, ok := m.byName[name]
	return c, ok
}

// Text returns the capture text or "" when absent.
func (m ASTMatch) Text(name string) string {
	if c, ok := m.byName[name]; ok {
		return c.Text
	}
	return ""
}

// Syntax is read-only AST access implemented by the parser (tree-sitter). It is
// consumed by AST-based rules; the interface lives in model to avoid a
// dependency from model on a concrete parser/tree-sitter implementation.
type Syntax interface {
	Language() Language
	// FindAll runs a tree-sitter query and returns matches with named captures.
	FindAll(query string) ([]ASTMatch, error)
	Close()
}

// NewASTMatch builds an ASTMatch and indexes captures by name.
func NewASTMatch(line int, caps []ASTCapture) ASTMatch {
	m := ASTMatch{Ordered: caps, byName: make(map[string]ASTCapture, len(caps)), Line: line}
	for _, c := range caps {
		m.byName[c.Name] = c
	}
	return m
}

// Line returns the 1-based display line text, or "" when out of range.
func (f *File) Line(n int) string {
	if n < 1 || n > len(f.Lines) {
		return ""
	}
	return strings.TrimRight(f.Lines[n-1], "\r")
}

// Match is a single rule hit within a file.
type Match struct {
	Line    int    // 1-based
	Snippet string // trimmed source line
	Message string // optional rule-specific override
}

// Rule is a detection pattern (PRD §4 & example GO-TEMP-001).
type Rule struct {
	ID         string
	Category   Category
	Severity   Severity
	Title      string
	Message    string
	FixHint    string
	Languages  []Language // empty means "all languages"
	Confidence float64    // 0.0–1.0
}

// Finding is a resolved rule match attached to a file.
type Finding struct {
	RuleID     string   `json:"rule_id"`
	Category   Category `json:"category"`
	Severity   Severity `json:"severity"`
	Title      string   `json:"title"`
	Message    string   `json:"message"`
	FixHint    string   `json:"fix_hint,omitempty"`
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Snippet    string   `json:"snippet"`
	Confidence float64  `json:"confidence"`
	Source     Source   `json:"source"`
	// References are external links (CVE/advisory URLs) — PRD §4.
	References []string `json:"references,omitempty"`
	// PriorityScore (0–100) and ScoreReason are the explainable ranking (PRD §11 M7).
	PriorityScore float64 `json:"priority_score,omitempty"`
	ScoreReason   string  `json:"score_reason,omitempty"`
	// InDiff marks findings whose line is part of a delta/PR range (PRD §3.4).
	InDiff bool `json:"in_diff,omitempty"`
}

// Summary aggregates scan statistics (PRD §9 report shape).
type Summary struct {
	FilesEnumerated int              `json:"files_enumerated"`
	FilesParsed     int              `json:"files_parsed"`
	FilesSkipped    int              `json:"files_skipped"`
	Errors          int              `json:"errors"`
	Findings        int              `json:"findings"`
	Baselined       int              `json:"baselined,omitempty"`
	BySeverity      map[Severity]int `json:"by_severity"`
}

// ScanResult is the top-level report document (schema_version = version.SchemaVersion).
type ScanResult struct {
	SchemaVersion string       `json:"schema_version"`
	Tool          ToolInfo     `json:"tool"`
	ScanID        string       `json:"scan_id"`
	Root          string       `json:"root"`
	DurationMs    int64        `json:"duration_ms"`
	Summary       Summary      `json:"summary"`
	Findings      []Finding    `json:"findings"`
	Dependencies  []Dependency `json:"dependencies,omitempty"`
	// AISummary is the optional narrative produced by AI-detector mode
	// (--ai-only, PRD §3.2). Empty for deterministic-only scans.
	AISummary string `json:"ai_summary,omitempty"`
	// Status is "partial" when at least one detection chunk failed, meaning the
	// file set was not fully reviewed; it is empty/"complete" otherwise. It is
	// wire-visible so CI/UI/agents can tell a partial scan from a clean one.
	Status string `json:"status,omitempty"`
	// ScanErrors lists non-fatal problems (e.g. AI enrichment/summary failures)
	// that did not change the detection result but are worth surfacing.
	ScanErrors []string `json:"scan_errors,omitempty"`
}

// Scan status values (ScanResult.Status).
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
)

// Partial reports whether the scan did not fully review the file set.
func (r *ScanResult) Partial() bool { return r != nil && r.Status == StatusPartial }

// LineRange is an inclusive 1-based line range (used for partial AI payloads).
type LineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// AIFile is a source file offered to an AI detector (PRD §3.2 AI-only mode).
// Content is the plain text; Language is the detected language (may be unknown).
// ID is a stable content-addressed handle (<relpath>#<hash>) the model can echo
// back to request the full content (repush); Ranges/Full describe whether the
// detector should send the whole file or only the changed excerpts.
type AIFile struct {
	RelPath  string      `json:"rel_path"`
	Content  string      `json:"-"`
	Language Language    `json:"language"`
	ID       string      `json:"id,omitempty"`
	Full     bool        `json:"full,omitempty"`
	Ranges   []LineRange `json:"ranges,omitempty"`
}

// Dependency is a package discovered from a manifest/lockfile (PRD §4.6).
type Dependency struct {
	Ecosystem string `json:"ecosystem"` // OSV ecosystem: Go, npm, PyPI, …
	Name      string `json:"name"`
	Version   string `json:"version"`
	File      string `json:"file,omitempty"` // manifest it came from
}

// ToolInfo identifies the binary that produced the report.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SortFindings orders findings deterministically: severity desc, then file, then line.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		wi, wj := SeverityWeight[fs[i].Severity], SeverityWeight[fs[j].Severity]
		if wi != wj {
			return wi > wj
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}

// SelectEnabledFilters identifies which findings pass a category/severity gate.
// Kept here (pure, testable); the scanner uses it while aggregating.
type Filter struct {
	Categories  map[Category]bool // nil = all
	SeverityMin Severity          // "" = all
}

func (f Filter) CategoryEnabled(c Category) bool {
	if f.Categories == nil {
		return true
	}
	return f.Categories[c]
}

func (f Filter) SeverityOK(s Severity) bool {
	if f.SeverityMin == "" {
		return true
	}
	return SeverityWeight[s] >= SeverityWeight[f.SeverityMin]
}
