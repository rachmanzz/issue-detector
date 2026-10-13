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
		Matcher: matchFunc(func(f *model.File) []model.Match { return matchRegexLines(f, goTempRe, 1) }),
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
			return matchRegexLines(f, hardcodedSecretRe, 1)
		}),
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
	if re == nil {
		return nil
	}
	var matches []model.Match
	seen := map[string]bool{}
	for i, text := range f.Lines {
		idx := re.FindStringIndex(text)
		if idx == nil {
			continue
		}
		lineNo := i + 1
		key := text
		if seen[key] {
			continue
		}
		seen[key] = true
		matches = append(matches, model.Match{
			Line:    lineNo,
			Snippet: strings.TrimSpace(text),
		})
		if len(matches) >= maxPerFile {
			break
		}
	}
	return matches
}

var (
	goTempRe = regexp.MustCompile(`ioutil\.TempFile|os\.CreateTemp\([^)]*,\s*""|tmp Name.*O_CREAT`)

	hardcodedSecretRe = regexp.MustCompile(`(?i)["']?(password|passwd|pwd|api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|bearer[_-]?token)["']?\s*[:=]\s*["'][^"'\s]{6,}`)

	privateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

	todoRe = regexp.MustCompile(`(?i)(//|#|;|<!--|\*)\s*(TODO|FIXME|HACK|XXX)\b`)

	debugOutRe = map[model.Language]*regexp.Regexp{
		model.LanguageJavaScript: regexp.MustCompile(`console\.(log|debug|warn)\s*\(`),
		model.LanguagePython:     regexp.MustCompile(`\bprint\s*\(`),
	}
)
