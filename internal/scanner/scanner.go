package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rachmanzz/fiber-extras/v3/queue"
	"github.com/rachmanzz/fiber-extras/v3/worker"
	"github.com/rachmanzz/issue-detector/internal/clone"
	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/delta"
	"github.com/rachmanzz/issue-detector/internal/deps"
	"github.com/rachmanzz/issue-detector/internal/fetcher"
	"github.com/rachmanzz/issue-detector/internal/gitx"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/parser"
	"github.com/rachmanzz/issue-detector/internal/posture"
	"github.com/rachmanzz/issue-detector/internal/rules"
	"github.com/rachmanzz/issue-detector/internal/score"
	"github.com/rachmanzz/issue-detector/internal/version"
)

// Options configures a scan run.
type Options struct {
	Root       string
	Config     config.Config
	Filter     model.Filter
	Log        *slog.Logger
	OnProgress func(Progress)
	Registry   *rules.Registry
	// ExtraRules are appended after builtins/external rules (e.g. rule packs).
	ExtraRules []*rules.Rule
	// Delta, when non-nil, restricts reported findings to changed lines (PRD §3.4).
	Delta *delta.Set
}

// Progress is emitted after each settled file.
type Progress struct {
	Scanned int
	Total   int
}

// Scanner runs the file scan pipeline over the fiber-extras worker + queue.
type Scanner struct {
	opts     Options
	log      *slog.Logger
	eng      *worker.Engine
	agg      *aggregator
	tracker  *completionTracker
	total    int
	registry *rules.Registry
	fused    func(Progress)
}

// New builds a Scanner; call Scan to run.
func New(opts Options) *Scanner {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(&nopWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	reg := opts.Registry
	if reg == nil {
		reg = rules.NewRegistry()
		if err := loadExternalRules(reg, opts.Config); err != nil {
			log.Warn("gagal memuat rule eksternal", "err", err)
		}
	}
	for _, r := range opts.ExtraRules {
		if _, exists := reg.Get(r.ID); !exists {
			reg.Add(r)
		}
	}
	return &Scanner{opts: opts, log: log, registry: reg, fused: opts.OnProgress}
}

// loadExternalRules adds user rule files/dirs (PRD §8) to the registry.
func loadExternalRules(reg *rules.Registry, cfg config.Config) error {
	paths := append([]string{}, cfg.Rules...)
	dir := cfg.RulesDir
	if dir == "" {
		dir = ".issue-detector/rules"
	}
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		paths = append(paths, dir)
	}
	if len(paths) == 0 {
		return nil
	}
	loaded, err := rules.LoadPaths(paths)
	if err != nil {
		return err
	}
	for _, r := range loaded {
		if _, exists := reg.Get(r.ID); exists {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		reg.Add(r)
	}
	return nil
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// Scan performs a full scan: fetch root → enumerate → queue per-file tasks →
// worker-parsed analysis → aggregate. Returns a report and, unless infra fails,
// a nil error (file-level failures are counted, not fatal).
func Scan(ctx context.Context, opts Options) (*model.ScanResult, error) {
	return New(opts).Scan(ctx)
}

func (s *Scanner) Scan(ctx context.Context) (*model.ScanResult, error) {
	start := time.Now()

	if s.opts.Config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.opts.Config.Timeout)
		defer cancel()
	}

	root, cleanup, err := fetcher.Fetch(ctx, fetcher.Options{
		Root:      s.opts.Root,
		RemoteURL: s.opts.Config.Remote,
	})
	if err != nil {
		return nil, err
	}
	defer cleanup()

	entries, err := fetcher.Enumerate(root, fetcher.Options{Ignore: s.opts.Config.Ignore})
	if err != nil {
		return nil, err
	}

	cfg := s.opts.Config
	scanID := uuid.NewString()

	jobs := cfg.Jobs
	if jobs < 1 {
		jobs = runtime.NumCPU()
	}
	sub := cfg.SubWorker
	if sub < 1 {
		sub = 5
	}

	eng := worker.New(
		worker.WithMaxWorkers(jobs),
		worker.WithSubWorkerLimit(sub),
		worker.WithShutdownTimeout(15*time.Second),
		worker.WithLogger(worker.NewSlogLogger(s.log)),
	).Start()
	defer eng.Shutdown()
	s.eng = eng
	// The queue consumer falls back to worker.GetDispatcher() when no dispatcher
	// is supplied; pointing it at our engine avoids spawning a default-logged
	// global engine (PRD-agent: quiet by default).
	worker.SetGlobalDispatcher(eng)

	s.tracker = newCompletionTracker(len(entries))
	s.agg = newAggregator()
	s.total = len(entries)

	queue.SetLogger(queue.NewSlogLogger(s.log))
	queue.SetDriver(queue.NewMemoryDriver())
	queue.RegisterHandler(TopicScanFile, s.onFileMessage)
	if _, err := queue.StartConsumer(
		queue.WithWorkerDispatcher(eng),
		queue.WithBatchSize(64),
		queue.WithPollInterval(5*time.Millisecond),
	); err != nil {
		return nil, fmt.Errorf("start queue consumer: %w", err)
	}
	defer queue.StopConsumer()

	s.log.Info("scan started", "scan_id", scanID, "files", len(entries), "root", root, "jobs", jobs)

	for i, e := range entries {
		payload, _ := json.Marshal(fileTask{Path: e.Path, RelPath: e.RelPath, Size: e.Size})
		if err := queue.Dispatch(ctx, TopicScanFile, payload,
			queue.WithPriority(filePriority(e.RelPath)),
		); err != nil {
			if s.tracker.complete(fmt.Sprintf("enqueue-%d", i)) {
				s.agg.commit(0, 0, 1, nil)
			}
			s.log.Error("dispatch failed", "file", e.RelPath, "error", err)
		}
	}

	if err := s.tracker.Wait(ctx); err != nil {
		s.log.Warn("scan did not settle; returning partial results", "scan_id", scanID, "error", err)
	}

	findings := s.agg.snapshot()
	sum := s.agg.summary()
	sum.FilesEnumerated = s.total

	// Repository-level health analysis (PRD §4.5). Deterministic, best-effort.
	if !s.opts.Config.NoGit {
		gitOpts := gitx.DefaultOptions(cfg.MaxFileSize)
		for _, gf := range gitx.Analyze(ctx, root, gitOpts) {
			if s.opts.Delta != nil && !s.opts.Delta.Contains(gf.File, gf.Line) {
				continue
			}
			gf.InDiff = s.opts.Delta != nil
			findings = append(findings, gf)
		}
	}

	// Posture scan of build/deploy config (PRD §11 M2). Deterministic.
	for _, pf := range posture.Analyze(entries) {
		if s.opts.Delta != nil && !s.opts.Delta.Contains(pf.File, pf.Line) {
			continue
		}
		pf.InDiff = s.opts.Delta != nil
		findings = append(findings, pf)
	}

	// Clone/duplicate detection (PRD §11 M3). Deterministic.
	for _, cf := range clone.Detect(entries, 0) {
		if s.opts.Delta != nil && !s.opts.Delta.Contains(cf.File, cf.Line) {
			continue
		}
		cf.InDiff = s.opts.Delta != nil
		findings = append(findings, cf)
	}

	// Dependency/manifest discovery (PRD §4.6). Offline; CVE lookup is done by
	// the caller (CLI) so the scanner stays deterministic and network-free.
	depRes := deps.Discover(entries)
	for _, df := range depRes.Findings {
		if s.opts.Delta != nil && !s.opts.Delta.Contains(df.File, df.Line) {
			continue
		}
		df.InDiff = s.opts.Delta != nil
		findings = append(findings, df)
	}

	findings = dedup(findings)
	model.SortFindings(findings)
	score.Apply(findings)
	sum.Findings = len(findings)
	sum.BySeverity = map[model.Severity]int{}
	for _, f := range findings {
		sum.BySeverity[f.Severity]++
	}

	return &model.ScanResult{
		SchemaVersion: version.SchemaVersion,
		Tool:          model.ToolInfo{Name: version.ToolName, Version: version.Version},
		ScanID:        scanID,
		Root:          root,
		DurationMs:    time.Since(start).Milliseconds(),
		Summary:       sum,
		Findings:      findings,
		Dependencies:  depRes.Deps,
	}, nil
}

// ruleResult couples a rule to its matches for one file.
type ruleResult struct {
	rule    *rules.Rule
	matches []model.Match
}

func (s *Scanner) onFileMessage(ctx context.Context, msg *queue.Message, pool worker.SubWorkerPool) error {
	var t fileTask
	if err := json.Unmarshal(msg.Payload, &t); err != nil {
		return s.settle(msg.ID, 0, 0, 1, nil)
	}

	f, err := parser.ReadFile(t.Path, t.RelPath, t.Size, s.opts.Config.MaxFileSize)
	if err != nil {
		s.log.Error("read file failed", "file", t.RelPath, "error", err)
		return s.settle(msg.ID, 0, 0, 1, nil)
	}

	if f.Skipped || f.Binary {
		return s.settle(msg.ID, 0, 1, 0, nil)
	}

	findings, err := s.analyze(ctx, pool, f)
	if err != nil {
		return err // transient: the consumer retries; nothing is committed yet
	}
	return s.settle(msg.ID, 1, 0, 0, findings)
}

// settle commits a file's outcome exactly once (tracker guards queue retries).
func (s *Scanner) settle(id string, parsed, skipped, errs int, findings []model.Finding) error {
	if !s.tracker.complete(id) {
		return nil
	}
	s.agg.commit(parsed, skipped, errs, findings)
	if s.fused != nil {
		s.fused(Progress{Scanned: s.agg.progress(), Total: s.total})
	}
	return nil
}

// analyze runs applicable rules for f, fanning out across the worker pool.
func (s *Scanner) analyze(ctx context.Context, pool worker.SubWorkerPool, f *model.File) ([]model.Finding, error) {
	filter := s.opts.Filter

	var applicable []*rules.Rule
	for _, r := range s.registry.All() {
		if rules.RuleForLanguage(r, f.Language) && filter.CategoryEnabled(r.Category) {
			applicable = append(applicable, r)
		}
	}

	// Attach an AST once for this file when a grammar exists; AST rules read it
	// read-only, line rules ignore it. Closed after all rules settle.
	if syn, err := parser.AttachSyntax(f); err == nil && syn != nil {
		defer syn.Close()
	}

	results := make([]ruleResult, len(applicable))
	for i, r := range applicable {
		i, r := i, r
		pool.Go(func(ctx context.Context) error {
			m, err := r.Matcher.Match(ctx, f)
			if err != nil {
				return fmt.Errorf("rule %s on %s: %w", r.ID, f.RelPath, err)
			}
			results[i] = ruleResult{rule: r, matches: m}
			return nil
		})
	}
	if err := pool.Wait(); err != nil {
		return nil, err
	}

	var findings []model.Finding
	for _, res := range results {
		if !filter.SeverityOK(res.rule.Severity) {
			continue
		}
		for _, m := range res.matches {
			// Delta scan (PRD §3.4): only report findings on changed lines.
			if s.opts.Delta != nil && !s.opts.Delta.Contains(f.RelPath, m.Line) {
				continue
			}
			snippet := m.Snippet
			if snippet == "" {
				snippet = f.Line(m.Line)
			}
			findings = append(findings, model.Finding{
				RuleID:     res.rule.ID,
				Category:   res.rule.Category,
				Severity:   res.rule.Severity,
				Title:      res.rule.Title,
				Message:    res.rule.Message,
				FixHint:    res.rule.FixHint,
				File:       f.RelPath,
				Line:       m.Line,
				Snippet:    snippet,
				Confidence: res.rule.Confidence,
				Source:     model.SourceRule,
				InDiff:     s.opts.Delta != nil,
			})
		}
	}
	return findings, nil
}

// filePriority biases the in-memory queue toward higher-value files: secret-ish
// paths get critical, source/config get high, the rest default.
func filePriority(rel string) queue.Priority {
	base := strings.ToLower(rel)
	switch {
	case secretLike(base):
		return queue.PriorityCritical
	case parser.DetectLanguage(rel) != model.LanguageUnknown || confExt(rel):
		return queue.PriorityHigh
	default:
		return queue.PriorityDefault
	}
}

func secretLike(base string) bool {
	for _, s := range []string{".env", ".pem", ".key", "credential", "secret", "password"} {
		if strings.Contains(base, s) {
			return true
		}
	}
	return false
}

func confExt(rel string) bool {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".yaml", ".yml", ".toml", ".json", ".ini", ".conf", ".env", ".dockerfile", ".cfg":
		return true
	}
	return false
}
