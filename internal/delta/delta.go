// Package delta implements delta / PR scanning (PRD §3.4): it computes which
// lines of which files changed relative to a base ref (or a patch file), so the
// scanner can report only findings that touch the change set.
package delta

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	dmp "github.com/sergi/go-diff/diffmatchpatch"

	"github.com/rachmanzz/issue-detector/internal/fetcher"
)

// ErrNotRepo is returned when delta scanning is requested outside a git repo.
var ErrNotRepo = errors.New("not a git repository")

// Range is an inclusive 1-based line range in the current file.
type Range struct {
	Start int
	End   int
}

// Set is the computed change set. Files maps a slash path to the changed line
// ranges within it; New reports whole files that are new relative to base.
type Set struct {
	Files map[string][]Range
	New   map[string]bool
}

// Empty reports whether the set has no changes.
func (s *Set) Empty() bool { return s == nil || (len(s.Files) == 0 && len(s.New) == 0) }

// Contains reports whether path/line is inside the change set. A nil set means
// delta filtering is disabled, so everything is contained.
func (s *Set) Contains(path string, line int) bool {
	if s == nil {
		return true
	}
	if s.New[path] {
		return true
	}
	for _, r := range s.Files[path] {
		if line >= r.Start && line <= r.End {
			return true
		}
	}
	return false
}

// FromBase computes the change set between the working tree at root and base.
// base may be a branch, tag, commit hash, or a relative revision (HEAD~2).
// Uncommitted edits on disk are included, which is what the agent loop needs.
func FromBase(ctx context.Context, root, base string) (*Set, error) {
	if base == "" {
		return nil, nil
	}
	repo, err := git.PlainOpen(root)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotRepo, root)
	}
	hash, err := repo.ResolveRevision(plumbing.Revision(base))
	if err != nil {
		return nil, fmt.Errorf("resolve base %q: %w", base, err)
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, fmt.Errorf("load base commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}

	entries, err := fetcher.Enumerate(root, fetcher.Options{})
	if err != nil {
		return nil, err
	}

	set := &Set{Files: map[string][]Range{}, New: map[string]bool{}}
	for _, e := range entries {
		select {
		case <-ctx.Done():
			return set, ctx.Err()
		default:
		}
		rel := filepath.ToSlash(e.RelPath)
		baseContent, berr := fileContent(tree, rel)
		if berr != nil {
			set.New[rel] = true // new file → all lines count
			continue
		}
		cur, cerr := os.ReadFile(e.Path)
		if cerr != nil {
			continue
		}
		if string(cur) == baseContent {
			continue
		}
		if rs := addedLines(baseContent, string(cur)); len(rs) > 0 {
			set.Files[rel] = rs
		}
	}
	return set, nil
}

// fileContent returns the blob content at path, or an error when absent.
func fileContent(tree *object.Tree, path string) (string, error) {
	f, err := tree.File(path)
	if err != nil {
		return "", err
	}
	return f.Contents()
}

// addedLines returns the 1-based line numbers in newText that are insertions
// relative to oldText, computed with a line-mode Myers diff.
func addedLines(oldText, newText string) []Range {
	d := dmp.New()
	a, b, lines := d.DiffLinesToChars(oldText, newText)
	diffs := d.DiffMain(a, b, false)
	diffs = d.DiffCharsToLines(diffs, lines)

	var ranges []Range
	line := 1 // current line in newText (1-based)
	for _, df := range diffs {
		n := countLines(df.Text)
		switch df.Type {
		case dmp.DiffInsert:
			if n > 0 {
				ranges = append(ranges, Range{Start: line, End: line + n - 1})
			}
			line += n
		case dmp.DiffEqual:
			line += n
		case dmp.DiffDelete:
			// deleted lines do not exist in newText
		}
	}
	return mergeRanges(ranges)
}

// countLines counts how many lines a diff fragment covers; fragments carry their
// trailing newline, so a missing trailing newline still counts as one line.
func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

// mergeRanges coalesces adjacent/overlapping ranges, sorted by start.
func mergeRanges(in []Range) []Range {
	if len(in) <= 1 {
		return in
	}
	sort.Slice(in, func(i, j int) bool { return in[i].Start < in[j].Start })
	out := in[:1]
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		if r.Start <= last.End+1 {
			if r.End > last.End {
				last.End = r.End
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

var hunkRe = regexp.MustCompile(`^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@`)

// FromPatchFile parses a unified diff (.diff/.patch) and returns the change set
// for added lines. Deleted files are ignored (nothing to scan).
func FromPatchFile(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePatch(string(data)), nil
}

// parsePatch scans a unified diff, collecting added line ranges per new file.
func parsePatch(text string) *Set {
	set := &Set{Files: map[string][]Range{}, New: map[string]bool{}}
	lines := strings.Split(text, "\n")

	var cur string
	var oldPath string
	var pending []Range
	flush := func() {
		if cur != "" && len(pending) > 0 {
			set.Files[cur] = mergeRanges(append(set.Files[cur], pending...))
		}
		pending = nil
	}

	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		switch {
		case strings.HasPrefix(ln, "--- "):
			oldPath = trimDiffPath(strings.TrimPrefix(ln, "--- "))

		case strings.HasPrefix(ln, "+++ "):
			flush()
			cur = trimDiffPath(strings.TrimPrefix(ln, "+++ "))
			if cur != "" {
				set.New[cur] = oldPath == "" // old side absent → new file
			}

		case hunkRe.MatchString(ln):
			m := hunkRe.FindStringSubmatch(ln)
			line, _ := strconv.Atoi(m[1])
			if m[2] != "" {
				if c, err := strconv.Atoi(m[2]); err == nil && c == 0 {
					// insertion-only hunk into an empty range still valid
					_ = c
				}
			}
			// consume hunk body
			for i+1 < len(lines) {
				body := lines[i+1]
				if body == "" || strings.HasPrefix(body, "@@") ||
					strings.HasPrefix(body, "diff ") || strings.HasPrefix(body, "+++ ") ||
					strings.HasPrefix(body, "--- ") {
					break
				}
				switch body[0] {
				case '+':
					pending = append(pending, Range{Start: line, End: line})
					line++
				case '-':
					// no line in new file
				case ' ':
					line++
				default:
					// unexpected marker: stop the hunk
					i = len(lines)
					continue
				}
				i++
			}
		}
	}
	flush()
	return set
}

// trimDiffPath normalizes a git diff path ("b/foo.go" → "foo.go") and maps the
// /dev/null sentinel to "".
func trimDiffPath(p string) string {
	p = strings.TrimSpace(p)
	// strip trailing tab+timestamp used by plain unified diffs
	if idx := strings.IndexByte(p, '\t'); idx >= 0 {
		p = p[:idx]
	}
	if p == "/dev/null" {
		return ""
	}
	p = strings.TrimPrefix(p, "a/")
	p = strings.TrimPrefix(p, "b/")
	return p
}
