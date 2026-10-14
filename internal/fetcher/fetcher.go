// Package fetcher locates source files from a local path or a remote git
// repository (PRD §5.1 "Fetcher"). Remote clones are shallow to stay cheap on
// large repos. Enumeration honors .gitignore / .issue-detectorignore and skips
// vendored/VCS dirs.
package fetcher

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	git "github.com/go-git/go-git/v5"
	gitignore "github.com/sabhiram/go-gitignore"
)

// Entry is a candidate source file discovered by the fetcher.
type Entry struct {
	Path    string // absolute path
	RelPath string // path relative to the scan root
	Size    int64
}

// DefaultIgnoreDirs are always skipped during walk.
var DefaultIgnoreDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".bzr": true,
	"node_modules": true, "vendor": true, "dist": true, "build": true,
	".idea": true, ".vscode": true, "__pycache__": true, ".mypy_cache": true,
	".tox": true, ".venv": true, "venv": true,
}

// Options configures source location.
type Options struct {
	Root      string // local directory to scan (or cache dir for remote)
	RemoteURL string // git URL to clone; requires Root as its parent dir
	Ignore    []string
}

// Fetch resolves the scan root: clones remote when RemoteURL is set,
// otherwise validates the local path. Returns the absolute root dir and a
// cleanup func (no-op for local dirs).
func Fetch(ctx context.Context, opts Options) (string, func(), error) {
	if opts.RemoteURL != "" {
		dir, err := cloneRemote(ctx, opts.RemoteURL, opts.Root)
		if err != nil {
			return "", nil, err
		}
		return dir, func() { _ = os.RemoveAll(dir) }, nil
	}

	abs, err := filepath.Abs(opts.Root)
	if err != nil {
		return "", nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", nil, fmt.Errorf("root %q: %w", opts.Root, err)
	}
	if !st.IsDir() {
		return "", nil, fmt.Errorf("root %q is not a directory", opts.Root)
	}
	return abs, func() {}, nil
}

// Enumerate walks root and returns candidate files sorted by RelPath.
// Honored ignore sources: <root>/.issue-detectorignore, <root>/.gitignore (and
// nested .gitignore files), plus Options.Ignore patterns. All patterns are kept
// in one ordered list per directory so .gitignore negation ("!pattern") and
// last-match-wins semantics work exactly as in git.
func Enumerate(root string, opts Options) ([]Entry, error) {
	rootLines := loadIgnoreLines(root)
	rootLines = append(rootLines, opts.Ignore...)
	stack := newIgnoreStack()
	if len(rootLines) > 0 {
		stack = stack.push("", gitignore.CompileIgnoreLines(rootLines...))
	}

	var out []Entry
	if err := walkDir(root, "", stack, &out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelPath < out[j].RelPath })
	return out, nil
}

// walkDir recurses from absRoot/relDir, carrying the stack of per-directory
// ignore matchers (root first) so nested .gitignore files apply to their subtree.
func walkDir(absRoot, relDir string, stack ignoreStack, out *[]Entry) error {
	dir := absRoot
	if relDir != "" {
		dir = filepath.Join(absRoot, filepath.FromSlash(relDir))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range entries {
		rel := de.Name()
		if relDir != "" {
			rel = relDir + "/" + de.Name()
		}
		if de.IsDir() {
			if DefaultIgnoreDirs[strings.ToLower(de.Name())] || stack.ignored(rel+"/") {
				continue
			}
			child := stack
			if lines := loadIgnoreFile(filepath.Join(dir, de.Name(), ".gitignore")); len(lines) > 0 {
				child = stack.push(rel, gitignore.CompileIgnoreLines(lines...))
			}
			if err := walkDir(absRoot, rel, child, out); err != nil {
				return err
			}
			continue
		}
		if stack.ignored(rel) {
			continue
		}
		info, ierr := de.Info()
		if ierr != nil {
			return ierr
		}
		*out = append(*out, Entry{Path: filepath.Join(dir, de.Name()), RelPath: rel, Size: info.Size()})
	}
	return nil
}

// loadIgnoreLines returns the root .issue-detectorignore + .gitignore lines,
// cleaned of CR and trailing spaces.
func loadIgnoreLines(root string) []string {
	var lines []string
	for _, name := range []string{".issue-detectorignore", ".gitignore"} {
		lines = append(lines, loadIgnoreFile(filepath.Join(root, name))...)
	}
	return lines
}

// loadIgnoreFile reads an ignore file and returns trimmed, non-empty lines.
func loadIgnoreFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	raw := strings.Split(string(data), "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, l)
	}
	return out
}

// ignoreStack is the chain of ignore matchers from the scan root down to a
// directory. Deeper matchers override shallower ones (git semantics).
type ignoreStack []levelMatcher

type levelMatcher struct {
	dir string // slash-relative dir from root ("" = root)
	gi  *gitignore.GitIgnore
}

func newIgnoreStack() ignoreStack { return ignoreStack{} }

func (s ignoreStack) push(dir string, gi *gitignore.GitIgnore) ignoreStack {
	next := make(ignoreStack, len(s), len(s)+1)
	copy(next, s)
	return append(next, levelMatcher{dir: dir, gi: gi})
}

// ignored reports whether rel is ignored, letting the deepest level that has an
// opinion decide (so a nested negation can re-include a file).
func (s ignoreStack) ignored(rel string) bool {
	ignored := false
	for _, lv := range s {
		sub := rel
		if lv.dir != "" {
			if !strings.HasPrefix(rel, lv.dir+"/") {
				continue
			}
			sub = rel[len(lv.dir)+1:]
		}
		if m, pat := lv.gi.MatchesPathHow(sub); pat != nil || m {
			ignored = m
		}
	}
	return ignored
}

func cloneRemote(ctx context.Context, url, cacheRoot string) (string, error) {
	if cacheRoot == "" {
		cacheRoot = os.TempDir()
	}
	dir, err := os.MkdirTemp(cacheRoot, "issue-detector-remote-*")
	if err != nil {
		return "", err
	}
	_, err = git.PlainCloneContext(ctx, dir, false, &git.CloneOptions{
		URL:      url,
		Depth:    1,
		Progress: io.Discard,
	})
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("clone %q: %w", url, err)
	}
	return dir, nil
}
