package scanrun

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/delta"
	"github.com/rachmanzz/issue-detector/internal/model"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func baseOpts(root string) Options {
	return Options{Root: root, Config: config.Config{}, Log: quiet(), Version: "test"}
}

// TestPrepareServesCachedResultAndResultIsNoop: a first scan persists the result
// and registers the ledger; a second unchanged Prepare serves it and its Result
// call must not overwrite the stored result.
func TestPrepareServesCachedResultAndResultIsNoop(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())
	ctx := context.Background()
	root := t.TempDir()

	p1 := Prepare(ctx, baseOpts(root))
	if p1.Cached != nil {
		t.Fatalf("run pertama tidak boleh di-serve dari cache")
	}
	if p1.Delta != nil {
		t.Fatalf("delta harus nil tanpa --base/--ai-only")
	}
	if p1.Store() == nil {
		t.Fatalf("store harus terbuka")
	}
	p1.Result(&model.ScanResult{ScanID: "first"})

	p2 := Prepare(ctx, baseOpts(root))
	if p2.Cached == nil {
		t.Fatalf("run kedua harus di-serve dari cache")
	}
	if p2.Cached.ScanID == "first" {
		t.Errorf("scan_id cache harus di-regenerate, masih %q", p2.Cached.ScanID)
	}
	// No-op: the served result must remain the originally stored one.
	p2.Result(p2.Cached)
	if got, ok, _ := p2.Store().LoadResult(root); !ok || got.ScanID != "first" {
		t.Errorf("Result pada hasil cache tidak boleh menimpa: ok=%v id=%q", ok, got.ScanID)
	}
}

// TestForceStillRefreshes: --force bypasses the read but the result is still
// persisted for a later unchanged run.
func TestForceStillRefreshes(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())
	ctx := context.Background()
	root := t.TempDir()

	Prepare(ctx, baseOpts(root)).Result(&model.ScanResult{ScanID: "first"})

	opts := baseOpts(root)
	opts.Force = true
	p := Prepare(ctx, opts)
	if p.Cached != nil {
		t.Fatalf("--force tidak boleh di-serve dari cache")
	}
	p.Result(&model.ScanResult{ScanID: "second"})
	if got, ok, _ := p.Store().LoadResult(root); !ok || got.ScanID != "second" {
		t.Errorf("--force harus refresh result.json: ok=%v id=%q", ok, got.ScanID)
	}
}

// TestExplicitDeltaNotPersisted: an explicit --base/--diff run neither writes
// result.json (it is filtered to the change set) nor advances the ledger marker.
func TestExplicitDeltaNotPersisted(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())
	ctx := context.Background()
	root := t.TempDir()

	opts := baseOpts(root)
	opts.ExplicitDelta = &delta.Set{Files: map[string][]delta.Range{}, New: map[string]bool{}}
	p := Prepare(ctx, opts)
	if p.Delta == nil {
		t.Fatalf("delta eksplisit harus diteruskan")
	}
	p.Result(&model.ScanResult{ScanID: "delta"})

	if _, ok, _ := p.Store().LoadResult(root); ok {
		t.Errorf("delta scan tidak boleh menyimpan result.json")
	}
	if _, has, _ := p.Store().LastItem(root); has {
		t.Errorf("delta scan eksplisit tidak boleh meng-advance ledger")
	}
}

// TestAIResultNotCachedButRegisters: AI results are excluded from the result
// cache but the change ledger still records the session.
func TestAIResultNotCachedButRegisters(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())
	ctx := context.Background()
	root := t.TempDir()

	opts := baseOpts(root)
	opts.AIOnly = true
	p := Prepare(ctx, opts)
	p.Result(&model.ScanResult{ScanID: "ai"})

	if _, ok, _ := p.Store().LoadResult(root); ok {
		t.Errorf("hasil AI tidak boleh masuk result cache")
	}
	if _, has, _ := p.Store().LastItem(root); !has {
		t.Errorf("ledger sesi harus tetap tercatat untuk hasil AI")
	}
}

// TestIncompleteScanNotRegistered: an incomplete scan (AI detector failure) must
// not advance the ledger, so the next run retries instead of skipping.
func TestIncompleteScanNotRegistered(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())
	ctx := context.Background()
	root := t.TempDir()

	opts := baseOpts(root)
	opts.AIOnly = true
	p := Prepare(ctx, opts)
	p.Result(&model.ScanResult{ScanID: "partial", Incomplete: true})

	if _, has, _ := p.Store().LastItem(root); has {
		t.Errorf("incomplete scan must not advance the ledger")
	}
}

// TestNoCacheDisablesStore: --no-cache must leave the store closed.
func TestNoCacheDisablesStore(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())
	opts := baseOpts(t.TempDir())
	opts.NoCache = true
	if p := Prepare(context.Background(), opts); p.Store() != nil {
		t.Errorf("--no-cache harus menonaktifkan store")
	}
}
