// Package gitx analyzes repository health (PRD §4.5): sensitive or oversized
// files tracked in HEAD, missing project files, and churn hotspots. It is
// best-effort and never fails the scan: a non-repo or unreadable history yields
// no findings.
package gitx

import (
	"context"
	"os"
	"path"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// Options tunes the git health analysis.
type Options struct {
	MaxFileSize  int64 // report tracked blobs larger than this
	ChurnCommits int   // how many recent commits to inspect for churn
	ChurnMin     int   // min changes for a file to count as a hotspot
}

// DefaultOptions returns sensible thresholds.
func DefaultOptions(maxFileSize int64) Options {
	return Options{MaxFileSize: maxFileSize, ChurnCommits: 200, ChurnMin: 8}
}

// Analyze returns git-health findings for the repo at root. A nil slice means no
// repository or no findings.
func Analyze(ctx context.Context, root string, opts Options) []model.Finding {
	repo, err := git.PlainOpen(root)
	if err != nil {
		return nil
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 1024 * 1024
	}
	if opts.ChurnCommits <= 0 {
		opts.ChurnCommits = 200
	}
	if opts.ChurnMin <= 0 {
		opts.ChurnMin = 8
	}

	var findings []model.Finding
	head, err := repo.Head()
	if err == nil {
		if commit, cerr := repo.CommitObject(head.Hash()); cerr == nil {
			if tree, terr := commit.Tree(); terr == nil {
				findings = append(findings, scanTree(tree, opts)...)
			}
		}
	}
	findings = append(findings, missingProjectFiles(root)...)
	findings = append(findings, churnHotspots(ctx, repo, opts)...)
	return findings
}

// sensitivePatterns are path fragments that should never be committed.
var sensitivePatterns = []string{".env", "id_rsa", "id_dsa", ".pem", ".p12", ".pfx", "credentials", "secrets.", ".npmrc", ".netrc"}
var sensitiveSuffix = []string{".key", ".pfx", ".p12", ".keystore"}

func scanTree(tree *object.Tree, opts Options) []model.Finding {
	var findings []model.Finding
	iter := tree.Files()
	defer iter.Close()
	_ = iter.ForEach(func(f *object.File) error {
		name := f.Name
		lower := strings.ToLower(path.Base(name))

		if isSensitive(lower) {
			findings = append(findings, model.Finding{
				RuleID: "GIT-001", Category: model.CategoryGit, Severity: model.SeverityCritical,
				Title: "Sensitive file committed", Message: "File berpotensi sensitif ter-commit ke repository.",
				FixHint: "Hapus dari riwayat (git filter-repo), rotasi kredensial, dan tambahkan ke .gitignore.",
				File:    name, Source: model.SourceRule, Confidence: 0.85,
			})
		}
		if f.Size > opts.MaxFileSize {
			findings = append(findings, model.Finding{
				RuleID: "GIT-002", Category: model.CategoryGit, Severity: model.SeverityLow,
				Title: "Large file tracked", Message: "File besar ter-commit; memperlambat clone dan menandakan binary/asset.",
				FixHint: "Pindahkan ke artefak/penyimpanan terpisah atau Git LFS.",
				File:    name, Source: model.SourceRule, Confidence: 0.7,
			})
		}
		return nil
	})
	return findings
}

func isSensitive(base string) bool {
	for _, p := range sensitivePatterns {
		if strings.Contains(base, p) {
			return true
		}
	}
	for _, s := range sensitiveSuffix {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	return false
}

// missingProjectFiles flags a repo lacking baseline hygiene files.
func missingProjectFiles(root string) []model.Finding {
	have := map[string]bool{}
	entries, err := readDirNames(root)
	if err != nil {
		return nil
	}
	for _, n := range entries {
		have[strings.ToLower(n)] = true
	}
	var out []model.Finding
	report := func(rule, title, msg string) {
		out = append(out, model.Finding{
			RuleID: rule, Category: model.CategoryGit, Severity: model.SeverityInfo,
			Title: title, Message: msg, File: ".",
			Source: model.SourceRule, Confidence: 0.6,
		})
	}
	if !hasPrefix(have, "readme") {
		report("GIT-003", "README tidak ada", "Repository tidak memiliki README.")
	}
	if !hasPrefix(have, "license") && !hasPrefix(have, "licence") {
		report("GIT-004", "Lisensi tidak ada", "Repository tidak memiliki file LICENSE.")
	}
	if !have[".gitignore"] {
		report("GIT-005", ".gitignore tidak ada", "Tanpa .gitignore, artefak/sensitif berisiko ter-commit.")
	}
	return out
}

// churnHotspots counts, over the last N commits, how often each file changes.
func churnHotspots(ctx context.Context, repo *git.Repository, opts Options) []model.Finding {
	iter, err := repo.Log(&git.LogOptions{})
	if err != nil {
		return nil
	}
	defer iter.Close()

	counts := map[string]int{}
	n := 0
	_ = iter.ForEach(func(c *object.Commit) error {
		if ctx.Err() != nil || n >= opts.ChurnCommits {
			return errStop
		}
		n++
		stats, serr := c.Stats()
		if serr != nil {
			return nil
		}
		for _, st := range stats {
			if st.Name != "" {
				counts[st.Name]++
			}
		}
		return nil
	})

	type kv struct {
		name string
		n    int
	}
	var hot []kv
	for name, c := range counts {
		if c >= opts.ChurnMin {
			hot = append(hot, kv{name, c})
		}
	}
	sort.Slice(hot, func(i, j int) bool {
		if hot[i].n != hot[j].n {
			return hot[i].n > hot[j].n
		}
		return hot[i].name < hot[j].name
	})
	if len(hot) > 10 {
		hot = hot[:10]
	}

	var out []model.Finding
	for _, h := range hot {
		out = append(out, model.Finding{
			RuleID: "GIT-006", Category: model.CategoryGit, Severity: model.SeverityInfo,
			Title: "Churn hotspot", Message: "File sering berubah — kandidat refactor / risiko bug.",
			File: h.name, Source: model.SourceRule, Confidence: 0.5,
		})
	}
	return out
}

var errStop = errStopSentinel{}

type errStopSentinel struct{}

func (errStopSentinel) Error() string { return "stop" }

// readDirNames returns the entry names of dir (files and directories).
func readDirNames(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names, nil
}

// hasPrefix reports whether any name starts with prefix (case-insensitive).
func hasPrefix(set map[string]bool, prefix string) bool {
	for n := range set {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}
