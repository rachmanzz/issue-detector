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
// Honored ignore sources: <root>/.issue-detectorignore, <root>/.gitignore,
// plus Options.Ignore patterns.
func Enumerate(root string, opts Options) ([]Entry, error) {
	patterns := make([]string, 0, len(opts.Ignore)+16)
	patterns = append(patterns, opts.Ignore...)
	for _, name := range []string{".issue-detectorignore", ".gitignore"} {
		if data, err := os.ReadFile(filepath.Join(root, name)); err == nil {
			patterns = append(patterns, strings.Split(string(data), "\n")...)
		}
	}
	matchers := compileIgnores(patterns)
	ign := &ignoreMatchers{matchers}

	var out []Entry
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if DefaultIgnoreDirs[strings.ToLower(d.Name())] || ign.match(rel+"/") {
				return filepath.SkipDir
			}
			return nil
		}
		if ign.match(rel) {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		out = append(out, Entry{Path: path, RelPath: rel, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(out, func(i, j int) bool { return out[i].RelPath < out[j].RelPath })
	return out, nil
}

type ignoreMatchers struct{ ms []*gitignore.GitIgnore }

func (im *ignoreMatchers) match(rel string) bool {
	if im == nil {
		return false
	}
	for _, m := range im.ms {
		if m.MatchesPath(rel) {
			return true
		}
	}
	return false
}

// compileIgnores builds matchers for the user-supplied ignore patterns.
func compileIgnores(patterns []string) []*gitignore.GitIgnore {
	if len(patterns) == 0 {
		return nil
	}
	out := make([]*gitignore.GitIgnore, 0, len(patterns))
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		out = append(out, gitignore.CompileIgnoreLines(p))
	}
	return out
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
