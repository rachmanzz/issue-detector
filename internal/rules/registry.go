// Package rules defines the rule engine (PRD §4). M0 ships line-based builtin
// rules; the Matcher abstraction leaves room for tree-sitter / Go predicate /
// WASM matchers in later milestones.
package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// Matcher inspects a file and returns zero or more matches.
type Matcher interface {
	Match(ctx context.Context, f *model.File) ([]model.Match, error)
}

// MatcherFunc adapts a function to the Matcher interface.
type MatcherFunc func(ctx context.Context, f *model.File) ([]model.Match, error)

func (fn MatcherFunc) Match(ctx context.Context, f *model.File) ([]model.Match, error) {
	return fn(ctx, f)
}

// NilMatcher matches nothing (rule disabled placeholder).
var NilMatcher Matcher = MatcherFunc(func(_ context.Context, _ *model.File) ([]model.Match, error) {
	return nil, nil
})

// Rule embeds the metadata (model.Rule) with its executable Matcher.
type Rule struct {
	model.Rule
	Matcher Matcher
}

// Registry holds the ordered set of builtin rules.
type Registry struct {
	rules []*Rule
}

// NewRegistry builds a registry with all builtin rules registered.
func NewRegistry() *Registry {
	r := &Registry{}
	for _, b := range builtinRules {
		r.Add(b)
	}
	for _, b := range securityRules {
		r.Add(b)
	}
	r.Add(taintRule)
	return r
}

// Add appends a rule to the registry.
func (r *Registry) Add(rule *Rule) {
	r.rules = append(r.rules, rule)
}

// Get returns a rule by ID.
func (r *Registry) Get(id string) (*Rule, bool) {
	for _, rule := range r.rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return nil, false
}

// All returns a copy of all rules in registration order.
func (r *Registry) All() []*Rule {
	out := make([]*Rule, len(r.rules))
	copy(out, r.rules)
	return out
}

// Fingerprint returns a stable hash of the rule set (IDs + metadata) so callers
// (e.g. the session cache) can key results on the rule set version and detect
// "same files, different rules" (PRD §10; roast v20).
func (r *Registry) Fingerprint() string {
	h := sha256.New()
	for _, rule := range r.rules {
		fmt.Fprintf(h, "%s|%s|%s|%v\n", rule.ID, rule.Category, rule.Severity, rule.Languages)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// RuleForLanguage reports whether a rule applies to the given file language.
func RuleForLanguage(rule *Rule, lang model.Language) bool {
	if len(rule.Languages) == 0 {
		return true
	}
	for _, l := range rule.Languages {
		if l == lang {
			return true
		}
	}
	return false
}
