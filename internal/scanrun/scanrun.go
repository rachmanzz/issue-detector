// Package scanrun coordinates the session/change and result cache (PRD §10)
// around a scan so the CLI, web and MCP paths share identical semantics:
//
//   - an automatic incremental delta for AI-only scans (diff vs the last checked
//     commit, including uncommitted edits),
//   - serving the stored result when nothing changed, and
//   - refreshing the ledger + result after a fresh scan.
//
// Callers still run scanner.Scan; this package only decides the effective delta
// and updates the cache.
package scanrun

import (
	"context"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/rachmanzz/issue-detector/internal/cache"
	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/delta"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/scanner"
)

// Options is a cache-aware scan request; the caller still runs scanner.Scan.
type Options struct {
	Root       string
	Config     config.Config
	Filter     model.Filter
	Log        *slog.Logger
	AIOnly     bool
	Detector   scanner.AIDetector
	OnProgress func(scanner.Progress)

	// AIEnabled folds AI enrichment into the "not cacheable" decision.
	AIEnabled bool
	// ExplicitDelta is a caller-provided change set (--base/--diff); nil = none.
	ExplicitDelta *delta.Set
	// Force bypasses serving a cached result but still refreshes it.
	Force bool
	// NoCache disables the session/result cache entirely.
	NoCache bool
	// Version is the tool version recorded in the ledger.
	Version string
}

// Prepared carries the cache decision for a single scan.
type Prepared struct {
	// Delta is the effective change set to pass to scanner.Options (may be nil).
	Delta *delta.Set
	// Cached, when non-nil, is a fresh stored result to serve instead of scanning.
	Cached *model.ScanResult

	store    *cache.Store
	opts     Options
	explicit bool
}

// Prepare opens the session store, computes the effective delta (including the
// automatic AI-only incremental base) and checks the result cache. It never
// fails: any cache error degrades to a plain full scan.
func Prepare(ctx context.Context, opts Options) *Prepared {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	p := &Prepared{opts: opts, explicit: opts.ExplicitDelta != nil}

	cfg := opts.Config
	ruleKey := scanner.RulesetFingerprint(cfg) + "|filter:" + FilterSignature(opts.Filter)

	if cfg.Remote == "" && !opts.NoCache && CacheEnabled(cfg.Cache) {
		if st, err := cache.Open(cache.Options{
			Mode:        cfg.Cache.Mode,
			Path:        cfg.Cache.Path,
			MaxItems:    cfg.Cache.MaxItems,
			RuleSetHash: ruleKey,
		}); err != nil {
			opts.Log.Warn("cache: gagal membuka", "err", err)
		} else {
			p.store = st
		}
	}

	p.Delta = opts.ExplicitDelta
	if opts.AIOnly && p.store != nil && !opts.Force && !p.explicit {
		p.Delta = p.autoIncremental(ctx)
	}

	// AI results are excluded from the result cache: their freshness is not
	// captured by the rule-set/version key, so we neither serve nor store them.
	if p.store != nil && !opts.Force && !opts.AIOnly && !opts.AIEnabled && p.Delta == nil {
		if fresh, err := p.store.Fresh(opts.Root, ruleKey, opts.Version); err != nil {
			opts.Log.Warn("cache: gagal cek kesegaran", "err", err)
		} else if fresh {
			if cached, ok, err := p.store.LoadResult(opts.Root); err != nil {
				opts.Log.Warn("cache: gagal memuat hasil", "err", err)
			} else if ok {
				cached.ScanID = uuid.NewString()
				p.Cached = &cached
				opts.Log.Info("cache: memakai hasil cache (tidak ada perubahan)", "dir", p.store.Dir())
			}
		}
	}
	return p
}

// Store exposes the session store (nil when the cache is disabled).
func (p *Prepared) Store() *cache.Store { return p.store }

// Result persists a freshly scanned result and appends the ledger entry. It is a
// no-op when the result was served from cache. Delta scans are never stored into
// result.json (they would poison a later full scan) and explicit --base/--diff
// runs do not advance the "fully checked" ledger marker.
func (p *Prepared) Result(res *model.ScanResult) {
	if p.store == nil || p.Cached != nil {
		return
	}
	if !p.opts.AIOnly && !p.opts.AIEnabled && p.Delta == nil {
		if err := p.store.SaveResult(p.opts.Root, *res); err != nil {
			p.opts.Log.Warn("cache: gagal menyimpan hasil", "err", err)
		}
	}
	if p.explicit {
		return
	}
	// Never advance the ledger for an incomplete scan (e.g. the AI detector
	// failed on some chunks): marking those files "checked" would make later
	// runs skip them, silently losing findings. Retry next run instead; chunks
	// that already succeeded stay in the detector cache, so retries are cheap.
	if res != nil && res.Incomplete {
		p.opts.Log.Warn("cache: ledger tidak di-advance (scan tidak lengkap)")
		return
	}
	if cres, err := p.store.Register(p.opts.Root, p.opts.Version); err != nil {
		p.opts.Log.Warn("cache: gagal register", "err", err, "dir", p.store.Dir())
	} else if cres.Skipped {
		p.opts.Log.Info("cache: tidak ada perubahan", "dir", p.store.Dir())
	} else {
		p.opts.Log.Info("cache: sesi terdaftar", "dir", p.store.Dir(),
			"commit_baru", len(cres.NewCommits), "file_berubah", len(cres.Changed))
	}
}

// autoIncremental diffs the working tree against the last checked commit from the
// cache, for AI-only scans. It returns a non-nil (possibly empty) change set, or
// nil to fall back to a full scan (no prior item, or the diff failed).
func (p *Prepared) autoIncremental(ctx context.Context) *delta.Set {
	root := p.opts.Root
	if _, hasPrev, _ := p.store.LastItem(root); !hasPrev {
		return nil
	}
	commits, changed, _ := p.store.Changed(root)
	head, _, _ := p.store.LastHead(root)
	switch {
	case len(commits) == 0 && len(changed) == 0:
		p.opts.Log.Info("ai-only: tidak ada perubahan sejak cache terakhir")
		return emptyDelta()
	case head != "":
		ds, err := delta.FromBase(ctx, root, head)
		if err != nil {
			p.opts.Log.Warn("ai-only: gagal diff sejak cache", "err", err, "head", shortHash(head))
			return nil
		}
		p.opts.Log.Info("ai-only: incremental sejak cache", "head", shortHash(head), "file_berubah", len(ds.Paths()))
		return ds
	default:
		ds := emptyDelta()
		for _, f := range changed {
			ds.New[filepath.ToSlash(f.File)] = true
		}
		p.opts.Log.Info("ai-only: incremental sejak cache (non-git)", "file_berubah", len(ds.Paths()))
		return ds
	}
}

// emptyDelta returns a non-nil change set with no changes (scan nothing).
func emptyDelta() *delta.Set {
	return &delta.Set{Files: map[string][]delta.Range{}, New: map[string]bool{}}
}

// CacheEnabled reports whether the session cache is enabled (nil pointer = on).
func CacheEnabled(c config.CacheConfig) bool {
	return c.Enabled == nil || *c.Enabled
}

// FilterSignature folds the active category/severity filter into the cache key so
// changing it invalidates a stored result.
func FilterSignature(f model.Filter) string {
	cats := make([]string, 0, len(f.Categories))
	for c, on := range f.Categories {
		if on {
			cats = append(cats, string(c))
		}
	}
	sort.Strings(cats)
	return strings.Join(cats, ",") + "|" + string(f.SeverityMin)
}

// shortHash renders the first 12 chars of a commit hash for logs.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
