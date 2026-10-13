package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// yamlRule is the on-disk rule schema (PRD §8).
type yamlRule struct {
	ID         string   `yaml:"id"`
	Category   string   `yaml:"category"`
	Severity   string   `yaml:"severity"`
	Title      string   `yaml:"title"`
	Message    string   `yaml:"message"`
	FixHint    string   `yaml:"fix_hint"`
	Confidence float64  `yaml:"confidence"`
	Languages  []string `yaml:"languages"`
	Match      struct {
		Kind    string `yaml:"kind"`    // regex | ast
		Pattern string `yaml:"pattern"` // kind=regex
		Query   string `yaml:"query"`   // kind=ast
	} `yaml:"match"`
}

// LoadFile parses one rule YAML file into a *Rule.
func LoadFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRule(data)
}

// ParseRule parses rule YAML bytes into a *Rule.
func ParseRule(data []byte) (*Rule, error) {
	var yr yamlRule
	if err := yaml.Unmarshal(data, &yr); err != nil {
		return nil, err
	}
	return yr.toRule()
}

// LoadPaths loads rules from files and/or directories (sorted for determinism).
func LoadPaths(paths []string) ([]*Rule, error) {
	var out []*Rule
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			matches, err := filepath.Glob(filepath.Join(p, "*.yaml"))
			if err != nil {
				return nil, err
			}
			yml, _ := filepath.Glob(filepath.Join(p, "*.yml"))
			matches = append(matches, yml...)
			for _, f := range matches {
				r, err := LoadFile(f)
				if err != nil {
					return nil, err
				}
				out = append(out, r)
			}
			continue
		}
		r, err := LoadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// toRule validates and converts a YAML rule into an executable Rule.
func (yr yamlRule) toRule() (*Rule, error) {
	if strings.TrimSpace(yr.ID) == "" {
		return nil, fmt.Errorf("rule id is required")
	}
	cat := model.Category(strings.ToLower(strings.TrimSpace(yr.Category)))
	if !isKnownCategory(cat) {
		return nil, fmt.Errorf("unknown category %q", yr.Category)
	}
	sev := model.Severity(strings.ToLower(strings.TrimSpace(yr.Severity)))
	if _, ok := model.SeverityWeight[sev]; !ok {
		return nil, fmt.Errorf("unknown severity %q", yr.Severity)
	}
	langs, err := parseLanguages(yr.Languages)
	if err != nil {
		return nil, err
	}
	conf := yr.Confidence
	if conf <= 0 || conf > 1 {
		conf = 0.7
	}

	meta := model.Rule{
		ID:         yr.ID,
		Category:   cat,
		Severity:   sev,
		Title:      yr.Title,
		Message:    yr.Message,
		FixHint:    yr.FixHint,
		Languages:  langs,
		Confidence: conf,
	}

	switch strings.ToLower(strings.TrimSpace(yr.Match.Kind)) {
	case "regex":
		re, err := regexp.Compile(yr.Match.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		return &Rule{Rule: meta, Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchRegexLines(f, re, 0)
		})}, nil
	case "ast":
		if yr.Match.Query == "" {
			return nil, fmt.Errorf("ast rule requires a query")
		}
		var lang model.Language
		if len(langs) > 0 {
			lang = langs[0]
		}
		return &Rule{Rule: meta, Matcher: ASTMatcher{Lang: lang, Query: yr.Match.Query}}, nil
	default:
		return nil, fmt.Errorf("unknown match.kind %q (want regex|ast)", yr.Match.Kind)
	}
}

func parseLanguages(in []string) ([]model.Language, error) {
	if len(in) == 0 {
		return nil, nil // all languages
	}
	out := make([]model.Language, 0, len(in))
	for _, s := range in {
		l := parseLanguage(s)
		if l == model.LanguageUnknown {
			return nil, fmt.Errorf("unknown language %q", s)
		}
		out = append(out, l)
	}
	return out, nil
}

func parseLanguage(s string) model.Language {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "go", "golang":
		return model.LanguageGo
	case "python", "py":
		return model.LanguagePython
	case "javascript", "js", "node":
		return model.LanguageJavaScript
	case "typescript", "ts":
		return model.LanguageTypeScript
	default:
		return model.LanguageUnknown
	}
}

// Language maps a language name to its model constant (public for the web lab).
func Language(s string) model.Language { return parseLanguage(s) }

func isKnownCategory(c model.Category) bool {
	for _, k := range model.AllCategories {
		if k == c {
			return true
		}
	}
	return false
}
