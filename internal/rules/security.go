package rules

import (
	"regexp"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// securityRules are the M2 "security depth" rules (PRD §4.1): injection,
// permissions, weak crypto, TOCTOU, info disclosure and log injection.
var securityRules = []*Rule{
	{
		Rule: model.Rule{
			ID:         "SEC-INJ-001",
			Category:   model.CategorySecurity,
			Severity:   model.SeverityHigh,
			Title:      "Possible injection (command/SQL/eval)",
			Message:    "Command/SQL/eval dijalankan atas string yang dirakit — berisiko injection bila input tak tepercaya.",
			FixHint:    "Gunakan API parameterized (prepared statement) atau exec tanpa shell; hindari eval.",
			Languages:  nil,
			Confidence: 0.65,
		},
		Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchCodeRegexes(f, injRes, 3)
		}),
	},
	{
		Rule: model.Rule{
			ID:         "SEC-PERM-001",
			Category:   model.CategorySecurity,
			Severity:   model.SeverityHigh,
			Title:      "World-writable permission",
			Message:    "Permission 0777/0007 membuat file/dir dapat ditulis semua pengguna.",
			FixHint:    "Gunakan permission ketat (mis. 0600 untuk file, 0755 untuk dir).",
			Languages:  nil,
			Confidence: 0.8,
		},
		Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchCodeRegexes(f, permRes, 2)
		}),
	},
	{
		Rule: model.Rule{
			ID:         "SEC-CRYPTO-001",
			Category:   model.CategorySecurity,
			Severity:   model.SeverityMedium,
			Title:      "Weak hash (MD5/SHA1)",
			Message:    "MD5/SHA1 tidak aman untuk password/tanda tangan/integritas.",
			FixHint:    "Gunakan bcrypt/argon2 untuk password, SHA-256+ untuk integritas.",
			Languages:  nil,
			Confidence: 0.6,
		},
		Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchCodeRegexes(f, cryptoRes, 3)
		}),
	},
	{
		Rule: model.Rule{
			ID:         "SEC-DISC-001",
			Category:   model.CategorySecurity,
			Severity:   model.SeverityMedium,
			Title:      "Information disclosure",
			Message:    "Debug mode aktif / detail error dapat bocor ke pengguna.",
			FixHint:    "Matikan debug di produksi; jangan kirim stack trace ke respons pengguna.",
			Languages:  nil,
			Confidence: 0.6,
		},
		Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchCodeRegexes(f, discRes, 2)
		}),
	},
	{
		Rule: model.Rule{
			ID:         "SEC-LOG-001",
			Category:   model.CategorySecurity,
			Severity:   model.SeverityLow,
			Title:      "Possible log injection",
			Message:    "Log merangkai input tanpa sanitasi — input berisi \\n dapat memalsukan baris log.",
			FixHint:    "Gunakan structured logging; escape/whitelist input sebelum di-log.",
			Languages:  nil,
			Confidence: 0.4,
		},
		Matcher: matchFunc(func(f *model.File) []model.Match {
			return matchCodeRegexes(f, logInjRes, 2)
		}),
	},
	{
		Rule: model.Rule{
			ID:         "SEC-RACE-001",
			Category:   model.CategorySecurity,
			Severity:   model.SeverityMedium,
			Title:      "TOCTOU (check-then-use)",
			Message:    "Cek keberadaan file diikuti operasi file terpisah — rentan race condition / symlink attack.",
			FixHint:    "Buka file langsung dengan flag O_CREAT|O_EXCL / tangani error, jangan cek dulu.",
			Languages:  []model.Language{model.LanguageGo, model.LanguagePython},
			Confidence: 0.5,
		},
		Matcher: matchFunc(matchStatThenOpen),
	},
}

var (
	injRes = []*regexp.Regexp{
		// Go: exec.Command("sh", "-c", ...) / powershell /C
		regexp.MustCompile(`exec\.Command(Context)?\(\s*"(sh|bash|/bin/sh|cmd|powershell)"\s*,\s*"-[cC]"`),
		// Go: db.Query/Exec with Sprintf or concatenation
		regexp.MustCompile(`\.(Query|QueryContext|Exec|ExecContext)\(\s*(fmt\.Sprintf\(|"[^"]*"\s*\+)`),
		// Python: os.system / shell=True / eval / exec
		regexp.MustCompile(`\b(os\.system|os\.popen|subprocess\.(call|run|Popen))\(`),
		regexp.MustCompile(`\bsubprocess\.\w+\([^)]*shell\s*=\s*True`),
		regexp.MustCompile(`\b(cursor|conn|db)\.execute\(\s*(f"|"[^"]*"\s*(%|\+|\.format\())`),
		// JS: child_process.exec / eval / new Function
		regexp.MustCompile(`\bchild_process\.(exec|execSync)\(`),
		regexp.MustCompile(`\bnew Function\(`),
	}
	permRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(chmod|Chmod|ChmodSync|FileMode|OpenFile|WriteFile|MkdirAll|Mkdir|Create|CreateTemp)\([^)]*(0o?777|0o?0007)`),
		regexp.MustCompile(`(?i)chmod\s+(-R\s+)?[0-7]?777\b`),
	}
	cryptoRes = []*regexp.Regexp{
		regexp.MustCompile(`\b(md5|sha1)\.(New|Sum)\b`),
		regexp.MustCompile(`\bhashlib\.(md5|sha1)\(`),
		regexp.MustCompile(`\bcreateHash\(\s*['"](md5|sha1)['"]`),
	}
	discRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bdebug\s*[:=]\s*(true|True)\b`),
		regexp.MustCompile(`["']net/http/pprof["']`),
		regexp.MustCompile(`(?i)(err|error|exception)\.(stack|StackTrace)\b`),
	}
	logInjRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(log|logger|logging)\.(info|warn|warning|error|debug|debugf|infof|warnf|errorf)\w*\([^)]*(f"|\+|\{[a-z_]+\})`),
		regexp.MustCompile(`\bLog\.(Printf?|Println)\([^)]*\+`),
	}
	statRes = regexp.MustCompile(`\bos\.Stat\(|\bos\.Lstat\(|\bos\.path\.exists\(`)
	openRes = regexp.MustCompile(`\bos\.Open(File)?\(|\bopen\(`)
)

// matchStatThenOpen flags a stat/exists check followed within a few lines by an
// open — a TOCTOU check-then-use (PRD §4.1 Race Condition / TOCTOU).
func matchStatThenOpen(f *model.File) []model.Match {
	const window = 5
	var matches []model.Match
	for i, line := range f.Lines {
		if isCommentLine(f.Language, line) || !statRes.MatchString(line) {
			continue
		}
		hi := i + window
		if hi >= len(f.Lines) {
			hi = len(f.Lines) - 1
		}
		for j := i + 1; j <= hi; j++ {
			if isCommentLine(f.Language, f.Lines[j]) || strings.Contains(f.Lines[j], "Defer") {
				continue
			}
			if openRes.MatchString(f.Lines[j]) {
				matches = append(matches, model.Match{Line: i + 1, Snippet: strings.TrimSpace(line)})
				break
			}
		}
		if len(matches) >= 3 {
			break
		}
	}
	return matches
}
