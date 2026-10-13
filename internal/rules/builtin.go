package rules

import (
	"context"
	"regexp"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// builtins is the M0 rule set (PRD examples GO-TEMP-001, secret patterns, TODO).
var builtinRules = []*Rule{
	{
		Rule: model.Rule{
			ID:         "GO-TEMP-001",
			Category:   model.CategorySecurity,
			Severity:   model.SeverityHigh,
			Title:      "Insecure temporary file creation",
			Message:    "File temporary dibuat dengan cara yang rentan race condition / symlink attack. Gunakan os.CreateTemp atau tempfile dengan O_EXCL.",
			FixHint:    "Gunakan os.CreateTemp / securefile dengan permission 0600.",
			Languages:  []model.Language{model.LanguageGo},
			Confidence: 0.85,
		},
		Matcher: ASTMatcher{
			Lang:  model.LanguageGo,
			Query: goTempQuery,
			On: func(f *model.File, m model.ASTMatch) (model.Match, bool) {
				pkg, fn := m.Text("pkg"), m.Text("fn")
				switch {
				case pkg == "ioutil" && fn == "TempFile":
					return model.Match{Line: m.Line, Snippet: snippetAt(f, m.Line)}, true
				case pkg == "os" && fn == "CreateTemp" && emptyFirstArg(m.Text("args")):
					return model.Match{Line: m.Line, Snippet: snippetAt(f, m.Line)}, true
				}
				return model.Match{}, false
			},
		},
	},
	{
		Rule: model.Rule{
			ID:         "SECRET-001",
			Category:   model.CategorySecrets,
			Severity:   model.SeverityHigh,
			Title:      "Hardcoded credential pattern",
			Message:    "Kredensial terlihat di-hardcode di kode. Pindahkan ke environment variable / secret manager.",
			FixHint:    "Baca nilai dari environment (os.Getenv) atau secret manager; jangan commit nilai asli.",
			Languages:  []model.Language{},
			Confidence: 0.7,
		},
		Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchRegexes(f, secretRes, 1)
		}),
	},
	{
		Rule: model.Rule{
			ID:         "PY-DESER-001",
			Category:   model.CategorySecurity,
			Severity:   model.SeverityHigh,
			Title:      "Unsafe deserialization",
			Message:    "Deserialisasi data tak tepercaya (yaml.load tanpa SafeLoader / pickle) dapat mengeksekusi kode.",
			FixHint:    "Gunakan yaml.safe_load atau json; hindari pickle untuk data dari luar.",
			Languages:  []model.Language{model.LanguagePython},
			Confidence: 0.8,
		},
		Matcher: ASTMatcher{
			Lang:  model.LanguagePython,
			Query: pyAttrCallQuery,
			On: func(f *model.File, m model.ASTMatch) (model.Match, bool) {
				obj, fn, args := m.Text("obj"), m.Text("fn"), m.Text("args")
				unsafe := (obj == "yaml" && fn == "load" && !strings.Contains(args, "SafeLoader")) ||
					(obj == "pickle" && (fn == "load" || fn == "loads")) ||
					(obj == "marshal" && fn == "loads")
				if !unsafe {
					return model.Match{}, false
				}
				return model.Match{Line: m.Line, Snippet: snippetAt(f, m.Line)}, true
			},
		},
	},
	{
		Rule: model.Rule{
			ID:         "SECRET-002",
			Category:   model.CategorySecrets,
			Severity:   model.SeverityCritical,
			Title:      "Private key material committed",
			Message:    "Blok kunci privat (PEM) terdeteksi di repository. Kunci seperti ini tidak boleh pernah di-commit.",
			FixHint:    "Hapus file ini dari riwayat git (git filter-repo), rotasi kunci, dan simpan di secret store.",
			Languages:  []model.Language{},
			Confidence: 0.95,
		},
		Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchRegexLines(f, privateKeyRe, 1)
		}),
	},
	{
		Rule: model.Rule{
			ID:         "TODO-001",
			Category:   model.CategoryTodo,
			Severity:   model.SeverityInfo,
			Title:      "TODO/FIXME marker",
			Message:    "Komentar TODO/FIXME/HACK/XXX ditemukan.",
			FixHint:    "Selesaikan atau buat task tracker, lalu hapus penanda ini.",
			Languages:  []model.Language{},
			Confidence: 0.9,
		},
		Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchRegexLines(f, todoRe, 1)
		}),
	},
	{
		Rule: model.Rule{
			ID:         "DBG-001",
			Category:   model.CategoryQuality,
			Severity:   model.SeverityLow,
			Title:      "Leftover debug output",
			Message:    "Pernyataan debugging tertinggal di kode.",
			FixHint:    "Hapus atau ganti dengan logging terstruktur yang dikontrol level.",
			Languages:  []model.Language{model.LanguageJavaScript, model.LanguagePython},
			Confidence: 0.6,
		},
		Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchRegexLines(f, debugOutRe[f.Language], 1)
		}),
	},
}

// matchFunc adapts a stateless match function.
type matchFunc func(f *model.File) []model.Match

func (fn matchFunc) Match(_ context.Context, f *model.File) ([]model.Match, error) {
	return fn(f), nil
}

func matchRegexLines(f *model.File, re *regexp.Regexp, maxPerFile int) []model.Match {
	return matchRegexes(f, []*regexp.Regexp{re}, maxPerFile)
}

// matchRegexes returns the first matching line for each distinct line across all
// patterns (deduplicated, capped at maxPerFile).
func matchRegexes(f *model.File, res []*regexp.Regexp, maxPerFile int) []model.Match {
	var matches []model.Match
	seen := map[int]bool{}
	for i, text := range f.Lines {
		lineNo := i + 1
		if seen[lineNo] {
			continue
		}
		for _, re := range res {
			if re == nil || !re.MatchString(text) {
				continue
			}
			seen[lineNo] = true
			matches = append(matches, model.Match{Line: lineNo, Snippet: strings.TrimSpace(text)})
			break
		}
		if maxPerFile > 0 && len(matches) >= maxPerFile {
			break
		}
	}
	return matches
}

// snippetAt returns the trimmed source line, or "" when out of range.
func snippetAt(f *model.File, line int) string {
	return strings.TrimSpace(f.Line(line))
}

// emptyFirstArg reports whether a call's argument list starts with an empty
// string literal, e.g. os.CreateTemp("", "app") — a predictable tmp dir.
func emptyFirstArg(args string) bool {
	t := strings.TrimSpace(args)
	t = strings.TrimPrefix(t, "(")
	return strings.HasPrefix(strings.TrimSpace(t), `""`)
}

var (
	// secretRes are high-signal credential patterns (PRD §4.1 Secret Leakage).
	secretRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)["']?(password|passwd|pwd|api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|bearer[_-]?token)["']?\s*[:=]\s*["'][^"'\s]{6,}`),
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                              // AWS access key id
		regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),                                        // Google API key
		regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),                                  // Slack token
		regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`),                                     // GitHub token
		regexp.MustCompile(`sk_live_[0-9A-Za-z]{16,}`),                                      // Stripe secret key
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), // JWT
	}

	privateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

	todoRe = regexp.MustCompile(`(?i)(//|#|;|<!--|\*)\s*(TODO|FIXME|HACK|XXX)\b`)

	debugOutRe = map[model.Language]*regexp.Regexp{
		model.LanguageJavaScript: regexp.MustCompile(`console\.(log|debug|warn)\s*\(`),
		model.LanguagePython:     regexp.MustCompile(`\bprint\s*\(`),
	}
)

// Tree-sitter queries for AST-based rules.
const (
	// goTempQuery captures the package + method of a selector call and its args.
	goTempQuery = `(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (field_identifier) @fn)
  arguments: (argument_list) @args)`

	// pyAttrCallQuery captures obj.method(args) calls (e.g. yaml.load(...)).
	pyAttrCallQuery = `(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @fn)
  arguments: (argument_list) @args)`
)
