// Package cache implements the session/change cache (PRD §10). It records, per
// project session, which commits and uncommitted files (with content hashes)
// were observed at each scan so later runs can detect changes without relying on
// a scan-result cache.
//
// Layout under the resolved main change path:
//
//	main_change_path/
//	  session_registery.json        # per-user registry of sessions
//	  session_<id>/
//	    registerar.json             # per-session change log (append-only items)
//
// Everything defaults to the per-user dir so nothing is written into the
// scanned project. The directory is resolved from config:
//
//	auto   (default): per-user global dir (~/.issues_detector/cache).
//	global : per-user global dir (~/.issues_detector/cache).
//	local  : next to the executable (opt-in).
//
// A custom path (or ISSUE_DETECTOR_CACHE_DIR, or ISSUE_DETECTOR_HOME) overrides
// the above.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/rachmanzz/issue-detector/internal/fetcher"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/parser"
)

const (
	registryFile    = "session_registery.json"
	registerarFile  = "registerar.json"
	resultFile      = "result.json"
	sessionPrefix   = "session_"
	lockName        = ".lock"
	maxCommits      = 200
	maxFileSize     = 1 << 20
	defaultMaxItems = 50
)

// Options configure cache location resolution and retention.
type Options struct {
	Mode        string // auto | global | local (empty = auto)
	Path        string // custom main change path (overrides Mode)
	ExePath     string // executable path (defaults to os.Executable)
	Home        string // home dir override (defaults to user home)
	Now         func() time.Time
	MaxItems    int    // max retained items per session (0 = defaultMaxItems)
	RuleSetHash string // rule-set fingerprint; part of the change key
}

// Store is a handle to the resolved main change path.
type Store struct {
	dir         string
	now         func() time.Time
	maxItems    int
	ruleSetHash string
	mu          sync.Mutex
}

// Open resolves the main change path and ensures it exists.
func Open(o Options) (*Store, error) {
	dir, err := resolveDir(o)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	maxItems := o.MaxItems
	if maxItems <= 0 {
		maxItems = defaultMaxItems
	}
	return &Store{dir: dir, now: now, maxItems: maxItems, ruleSetHash: o.RuleSetHash}, nil
}

// Dir returns the resolved main change path.
func (s *Store) Dir() string { return s.dir }

// SessionID derives a stable session id from a project path.
func SessionID(projectPath string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(projectPath)))
	return hex.EncodeToString(sum[:])[:12]
}

// RegistryEntry maps a session id to its project path.
type RegistryEntry struct {
	ID          string `json:"id"`
	ProjectPath string `json:"project_path"`
}

type registry struct {
	AppVersion string          `json:"app_version"`
	Registery  []RegistryEntry `json:"registery"`
}

// UncommitFile is one uncommitted file with its content hash.
type UncommitFile struct {
	File string `json:"f"`
	Hash string `json:"hash"`
}

// Item is one registration event in a session's change log.
type Item struct {
	RegisterarID   string         `json:"registerar_id"`
	RegisterarTime string         `json:"registerar_time"`
	CommitIDs      []string       `json:"commit_ids"`
	UncommitFiles  []UncommitFile `json:"uncommit_files"`
	Head           string         `json:"head,omitempty"` // HEAD commit at scan time (git only)
	RuleSetHash    string         `json:"rule_set_hash,omitempty"`
	ToolVersion    string         `json:"tool_version,omitempty"`
}

// Result reports what a Register call observed relative to the previous item.
// It is the read side of the cache: consumers can use Changed to drive delta /
// incremental scans without re-reading files themselves.
type Result struct {
	NewCommits []string       // commits not seen in prior items
	Changed    []UncommitFile // files new/changed/removed vs the previous item
	Skipped    bool           // true when nothing changed (no item appended)
	ItemID     string         // id of the appended item (empty when skipped)
}

type registerar struct {
	SessionID   string `json:"session_id"`
	ProjectPath string `json:"project_path"`
	CreatedAt   string `json:"created_at"`
	Items       []Item `json:"items"`
}

// Register records one item for the project's session: new commits since the
// last recorded item plus the current uncommitted file hashes. It creates the
// session directory and registry entry on first use. Non-git projects record
// all scanned files as uncommitted.
//
// The read-modify-write is guarded by a cross-process advisory lock, items are
// trimmed to Store.maxItems (LRU), and a no-op rescan appends nothing
// (idempotent). It returns a Result describing the delta vs the previous item.
func (s *Store) Register(projectPath, appVersion string) (Result, error) {
	abs, err := filepath.Abs(projectPath)
	if err != nil {
		return Result{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	unlock, err := s.lock()
	if err != nil {
		return Result{}, err
	}
	defer unlock()

	id := SessionID(abs)

	reg, err := s.loadRegistry()
	if err != nil {
		return Result{}, err
	}
	reg.AppVersion = appVersion
	if !regHas(reg, id) {
		reg.Registery = append(reg.Registery, RegistryEntry{ID: id, ProjectPath: abs})
	}

	sessionDir := filepath.Join(s.dir, sessionPrefix+id)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return Result{}, err
	}

	rr, err := loadRegisterar(filepath.Join(sessionDir, registerarFile))
	if err != nil {
		return Result{}, err
	}
	if rr.SessionID == "" {
		rr.SessionID = id
		rr.ProjectPath = abs
		rr.CreatedAt = s.now().UTC().Format(time.RFC3339)
	}

	known := map[string]bool{}
	for _, it := range rr.Items {
		for _, c := range it.CommitIDs {
			known[c] = true
		}
	}
	commits, files := collectChanges(abs, known)

	var prev []UncommitFile
	var prevKey Item
	if len(rr.Items) > 0 {
		prevKey = rr.Items[len(rr.Items)-1]
		prev = prevKey.UncommitFiles
	}
	changed := diffFiles(prev, files)

	res := Result{NewCommits: commits, Changed: changed}
	unchanged := len(rr.Items) > 0 && len(commits) == 0 && len(changed) == 0 &&
		prevKey.RuleSetHash == s.ruleSetHash && prevKey.ToolVersion == appVersion

	if unchanged {
		// Nothing changed: keep the item count flat (no unbounded growth).
		res.Skipped = true
		if err := writeJSON(filepath.Join(s.dir, registryFile), reg); err != nil {
			return res, err
		}
		return res, nil
	}

	now := s.now().UTC()
	res.ItemID = newItemID(id, now, commits, files)
	rr.Items = append(rr.Items, Item{
		RegisterarID:   res.ItemID,
		RegisterarTime: now.Format(time.RFC3339),
		CommitIDs:      commits,
		UncommitFiles:  files,
		Head:           headCommit(abs),
		RuleSetHash:    s.ruleSetHash,
		ToolVersion:    appVersion,
	})
	if len(rr.Items) > s.maxItems {
		rr.Items = append([]Item(nil), rr.Items[len(rr.Items)-s.maxItems:]...)
	}

	if err := writeJSON(filepath.Join(sessionDir, registerarFile), rr); err != nil {
		return res, err
	}
	return res, writeJSON(filepath.Join(s.dir, registryFile), reg)
}

// lock takes an exclusive cross-process advisory lock on the main change path.
// The returned func releases it. flock is released automatically on process
// exit, so a crashed scanner never leaves a stale lock.
func (s *Store) lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.dir, lockName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = unlockFile(f)
		f.Close()
	}, nil
}

// LastItem returns the most recent recorded item for projectPath, if any.
func (s *Store) LastItem(projectPath string) (Item, bool, error) {
	abs, err := filepath.Abs(projectPath)
	if err != nil {
		return Item{}, false, err
	}
	rr, err := loadRegisterar(filepath.Join(s.dir, sessionPrefix+SessionID(abs), registerarFile))
	if err != nil {
		return Item{}, false, err
	}
	if len(rr.Items) == 0 {
		return Item{}, false, nil
	}
	return rr.Items[len(rr.Items)-1], true, nil
}

// LastHead returns the HEAD commit recorded for projectPath's most recent item.
// ok is false when there is no prior item or the root is not a git repo (no
// HEAD was recorded). Consumers use it as the base for incremental diffs.
func (s *Store) LastHead(projectPath string) (head string, ok bool, err error) {
	it, has, err := s.LastItem(projectPath)
	if err != nil || !has {
		return "", false, err
	}
	return it.Head, it.Head != "", nil
}

// Changed reports the delta of the working tree vs the last recorded item
// without writing anything: new commits since the last scan and files that are
// new/changed/removed. This is the read side consumers use for incremental work.
func (s *Store) Changed(projectPath string) ([]string, []UncommitFile, error) {
	abs, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, err
	}
	rr, err := loadRegisterar(filepath.Join(s.dir, sessionPrefix+SessionID(abs), registerarFile))
	if err != nil {
		return nil, nil, err
	}
	known := map[string]bool{}
	for _, it := range rr.Items {
		for _, c := range it.CommitIDs {
			known[c] = true
		}
	}
	commits, files := collectChanges(abs, known)
	var prev []UncommitFile
	if len(rr.Items) > 0 {
		prev = rr.Items[len(rr.Items)-1].UncommitFiles
	}
	return commits, diffFiles(prev, files), nil
}

// SaveResult persists the last full scan result for projectPath inside its
// session directory (result.json). Best-effort: callers may log and ignore the
// error without failing the scan.
func (s *Store) SaveResult(projectPath string, res model.ScanResult) error {
	dir, err := s.sessionDir(projectPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(filepath.Join(dir, resultFile), res)
}

// LoadResult returns the last saved scan result for projectPath, if any.
func (s *Store) LoadResult(projectPath string) (model.ScanResult, bool, error) {
	dir, err := s.sessionDir(projectPath)
	if err != nil {
		return model.ScanResult{}, false, err
	}
	var res model.ScanResult
	ok, err := readJSON(filepath.Join(dir, resultFile), &res)
	if err != nil {
		return model.ScanResult{}, false, err
	}
	return res, ok, nil
}

// Fresh reports whether the saved result for projectPath is still valid and can
// be served without rescanning: a result is stored, the last recorded item used
// the same rule-set fingerprint and tool version, and nothing changed since (no
// new commits, no added/changed/removed files). A false verdict, even with a
// nil error, always means "rescan".
func (s *Store) Fresh(projectPath, ruleSetHash, toolVersion string) (bool, error) {
	dir, err := s.sessionDir(projectPath)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(filepath.Join(dir, resultFile)); err != nil {
		return false, nil
	}
	last, ok, err := s.LastItem(projectPath)
	if err != nil || !ok {
		return false, err
	}
	if last.RuleSetHash != ruleSetHash || last.ToolVersion != toolVersion {
		return false, nil
	}
	commits, changed, err := s.Changed(projectPath)
	if err != nil {
		return false, err
	}
	return len(commits) == 0 && len(changed) == 0, nil
}

// sessionDir returns the absolute session directory for projectPath.
func (s *Store) sessionDir(projectPath string) (string, error) {
	abs, err := filepath.Abs(projectPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, sessionPrefix+SessionID(abs)), nil
}

// diffFiles returns files whose hash differs from prev (new/changed) plus files
// present in prev but gone now (reported with empty hash = removed).
func diffFiles(prev, cur []UncommitFile) []UncommitFile {
	pm := make(map[string]string, len(prev))
	for _, f := range prev {
		pm[f.File] = f.Hash
	}
	var out []UncommitFile
	seen := make(map[string]bool, len(cur))
	for _, f := range cur {
		seen[f.File] = true
		if h, ok := pm[f.File]; !ok || h != f.Hash {
			out = append(out, f)
		}
	}
	for _, f := range prev {
		if !seen[f.File] {
			out = append(out, UncommitFile{File: f.File, Hash: ""})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

func (s *Store) loadRegistry() (registry, error) {
	var r registry
	if _, err := readJSON(filepath.Join(s.dir, registryFile), &r); err != nil {
		return r, err
	}
	return r, nil
}

func loadRegisterar(path string) (registerar, error) {
	var r registerar
	if _, err := readJSON(path, &r); err != nil {
		return r, err
	}
	return r, nil
}

func regHas(r registry, id string) bool {
	for _, e := range r.Registery {
		if e.ID == id {
			return true
		}
	}
	return false
}

func newItemID(sessionID string, t time.Time, commits []string, files []UncommitFile) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d", sessionID, t.UnixNano())
	for _, c := range commits {
		fmt.Fprintf(h, "|c:%s", c)
	}
	for _, f := range files {
		fmt.Fprintf(h, "|f:%s:%s", f.File, f.Hash)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// collectChanges returns (new commits, uncommitted files) for root. known holds
// commit hashes already recorded so only new commits are reported. A non-git
// root falls back to hashing every scanned file.
func collectChanges(root string, known map[string]bool) ([]string, []UncommitFile) {
	repo, err := git.PlainOpen(root)
	if err != nil {
		return nil, hashAll(root)
	}
	return newCommits(repo, known), uncommitted(repo, root)
}

// headCommit returns the current HEAD commit hash of root, or "" when root is
// not a git repository (or has no commits yet).
func headCommit(root string) string {
	repo, err := git.PlainOpen(root)
	if err != nil {
		return ""
	}
	ref, err := repo.Head()
	if err != nil {
		return ""
	}
	return ref.Hash().String()
}

var errStop = errors.New("stop")

func newCommits(repo *git.Repository, known map[string]bool) []string {
	head, err := repo.Head()
	if err != nil {
		return nil
	}
	iter, err := repo.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return nil
	}
	defer iter.Close()

	var out []string
	_ = iter.ForEach(func(c *object.Commit) error {
		hash := c.Hash.String()
		if known[hash] {
			return errStop
		}
		out = append(out, hash)
		if len(out) >= maxCommits {
			return errStop
		}
		return nil
	})
	// Oldest → newest for a chronological log.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func uncommitted(repo *git.Repository, root string) []UncommitFile {
	wt, err := repo.Worktree()
	if err != nil {
		return nil
	}
	st, err := wt.Status()
	if err != nil {
		return nil
	}
	var out []UncommitFile
	for p, fs := range st {
		if fs.Staging == git.Unmodified && fs.Worktree == git.Unmodified {
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(p))
		hash := ""
		if fi, err := os.Stat(abs); err == nil && !fi.IsDir() && fi.Size() <= maxFileSize {
			hash = hashFile(abs)
		}
		out = append(out, UncommitFile{File: p, Hash: hash})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

func hashAll(root string) []UncommitFile {
	entries, err := fetcher.Enumerate(root, fetcher.Options{})
	if err != nil {
		return nil
	}
	out := make([]UncommitFile, 0, len(entries))
	for _, e := range entries {
		if e.Size > maxFileSize || parser.IsBinaryExt(e.Path) {
			continue
		}
		out = append(out, UncommitFile{File: e.RelPath, Hash: hashFile(e.Path)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// --- path resolution ----------------------------------------------------

func resolveDir(o Options) (string, error) {
	if p := strings.TrimSpace(os.Getenv("ISSUE_DETECTOR_CACHE_DIR")); p != "" {
		return p, nil
	}
	if p := strings.TrimSpace(o.Path); p != "" {
		// A relative custom path is anchored under the per-user dir, never the
		// CWD, so the cache cannot land inside the scanned project (PRD §7.1).
		if filepath.IsAbs(p) {
			return p, nil
		}
		g, gerr := globalDir(o.Home)
		if gerr != nil {
			return "", gerr
		}
		return filepath.Join(g, p), nil
	}
	switch strings.ToLower(strings.TrimSpace(o.Mode)) {
	case "global", "auto", "":
		return globalDir(o.Home)
	case "local":
		return localDir(o.ExePath)
	default:
		return "", fmt.Errorf("cache: mode tidak dikenal %q", o.Mode)
	}
}

func localDir(exe string) (string, error) {
	dir, err := exeDir(exe)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ".issues_detector"), nil
}

func exeDir(exe string) (string, error) {
	if exe == "" {
		e, err := os.Executable()
		if err != nil {
			return "", err
		}
		exe = e
	}
	return filepath.Dir(exe), nil
}

func globalDir(explicit string) (string, error) {
	home := explicit
	if home == "" {
		home = os.Getenv("ISSUE_DETECTOR_HOME")
	}
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		home = h
	}
	return filepath.Join(home, ".issues_detector", "cache"), nil
}

// --- json helpers -------------------------------------------------------

func readJSON(path string, v any) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
