// Package ai provides optional AI enrichment of findings (PRD §6.3 Mode B):
// a provider abstraction (OpenAI-compatible / Gemini), secret redaction before
// any network call, a response cache, and a token budget. AI output is tagged
// source=ai and is excluded from --fail-on by default (PRD §3.5).
package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/score"
)

// PromptVersion bumps when the prompt/response contract changes (cache key).
const PromptVersion = "8"

// Config configures enrichment.
type Config struct {
	Provider     string // openai | gemini
	Model        string
	BaseURL      string
	APIKey       string
	MaxFindings  int // cap findings to enrich
	BudgetTokens int // approx token budget across the run
	CacheDir     string
	// Format selects the AI-only detector reply format: "block" (default,
	// line-oriented key=value blocks — resilient to truncated replies) or
	// "json". The parser always accepts both as a fallback.
	Format       string
	ScoreWeights score.Weights // priority-score coefficients (race-free scoring)
}

// FormatBlock and FormatJSON are the accepted AI detector reply formats.
const (
	FormatBlock = "block"
	FormatJSON  = "json"
)

// normalizeFormat maps arbitrary input to a supported format (default block).
func normalizeFormat(f string) string {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case FormatJSON:
		return FormatJSON
	default:
		return FormatBlock
	}
}

// Enricher performs AI enrichment with redaction, cache and budget. It also
// implements AI-detector mode (Detect) which reuses the same provider, cache
// directory and token budget.
type Enricher struct {
	cfg      Config
	provider Provider
	cache    *cache
	dcache   *strCache
	used     int
}

// New builds an Enricher. It requires a known provider; an API key is only
// mandatory when no custom BaseURL is set (local OpenAI-compatible servers such
// as Ollama/vLLM need no key).
func New(cfg Config) (*Enricher, error) {
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = 25
	}
	if cfg.BudgetTokens <= 0 {
		cfg.BudgetTokens = 100000
	}
	cfg.Format = normalizeFormat(cfg.Format)
	// Anchor the AI cache under the per-user dir so a relative cache_dir can
	// never write into the scanned project (PRD §7.1). StatePath resolves
	// relative paths against ~/.issues_detector, not the CWD.
	cfg.CacheDir = config.StatePath(cfg.CacheDir, "ai-cache")
	if cfg.Model == "" {
		if cfg.BaseURL != "" {
			return nil, fmt.Errorf("ai: model wajib diisi saat memakai base_url (server OpenAI-compatible apa pun)")
		}
		switch cfg.Provider {
		case "gemini":
			cfg.Model = "gemini-1.5-flash"
		default:
			cfg.Model = "gpt-4o-mini"
		}
	}
	p, err := newProvider(cfg)
	if err != nil {
		return nil, err
	}
	return &Enricher{
		cfg:      cfg,
		provider: p,
		cache:    loadCache(cfg.CacheDir),
		dcache:   loadStrCache(filepath.Join(cfg.CacheDir, "ai-detect-cache.json")),
	}, nil
}

type enrichOut struct {
	Explanation string   `json:"explanation"`
	Remediation string   `json:"remediation"`
	Confidence  *float64 `json:"confidence,omitempty"`
}

// Probe sends a minimal prompt to verify provider wiring (config + base_url +
// key). Returns the raw model reply.
func Probe(ctx context.Context, cfg Config) (string, error) {
	e, err := New(cfg)
	if err != nil {
		return "", err
	}
	return e.provider.Complete(ctx, "Reply with exactly: ok", false)
}

// Candidates counts findings that are eligible for enrichment (high/critical,
// not already AI-sourced).
func Candidates(findings []model.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Source == model.SourceAI {
			continue
		}
		if model.SeverityWeight[f.Severity] >= model.SeverityWeight[model.SeverityHigh] {
			n++
		}
	}
	return n
}

// Enrich augments high/critical findings with AI explanation + remediation. It
// is best-effort: a failing finding is skipped, but the first error is returned
// so callers can surface a dead endpoint (instead of silently doing nothing).
func (e *Enricher) Enrich(ctx context.Context, res *model.ScanResult) (int, error) {
	enriched := 0
	var lastErr error
	var added []model.Finding
	for _, f := range res.Findings {
		if f.Source == model.SourceAI {
			continue
		}
		if model.SeverityWeight[f.Severity] < model.SeverityWeight[model.SeverityHigh] {
			continue
		}
		if enriched >= e.cfg.MaxFindings || e.used >= e.cfg.BudgetTokens {
			break
		}
		prompt := buildPrompt(f)
		if e.used+approxTokens(prompt) > e.cfg.BudgetTokens {
			break
		}
		out, err := e.cached(ctx, f, prompt)
		if err != nil {
			lastErr = err
			continue
		}
		e.used += approxTokens(prompt)
		af := model.Finding{
			RuleID: f.RuleID + ":ai", Category: f.Category, Severity: f.Severity,
			Title: "AI: " + f.Title, Message: strings.TrimSpace(out.Explanation),
			FixHint: strings.TrimSpace(out.Remediation), File: f.File, Line: f.Line,
			Snippet: f.Snippet, Confidence: confOr(out.Confidence, 0.5), Source: model.SourceAI,
		}
		added = append(added, af)
		enriched++
	}
	if len(added) > 0 {
		res.Findings = append(res.Findings, added...)
		model.SortFindings(res.Findings)
		score.Apply(res.Findings, e.cfg.ScoreWeights)
		res.Summary.Findings = len(res.Findings)
		res.Summary.BySeverity = map[model.Severity]int{}
		for _, f := range res.Findings {
			res.Summary.BySeverity[f.Severity]++
		}
		e.cache.save()
	}
	return enriched, lastErr
}

func (e *Enricher) cached(ctx context.Context, f model.Finding, prompt string) (enrichOut, error) {
	key := cacheKey(e.cfg.Model, f)
	if out, ok := e.cache.get(key); ok {
		return out, nil
	}
	raw, err := e.provider.Complete(ctx, prompt, true)
	if err != nil {
		return enrichOut{}, err
	}
	out, perr := parseEnrich(raw)
	if perr != nil {
		// Do not cache an unparseable reply: a model glitch must not become a
		// permanent "explanation", and the finding is retried next run.
		return enrichOut{}, perr
	}
	e.cache.put(key, out)
	return out, nil
}

func buildPrompt(f model.Finding) string {
	var b strings.Builder
	b.WriteString("You are a security reviewer. Answer ONLY with a JSON object ")
	b.WriteString(`{"explanation": "...", "remediation": "...", "confidence": 0.0-1.0}.`)
	b.WriteString("\nrule: " + f.RuleID)
	b.WriteString("\nseverity: " + string(f.Severity))
	b.WriteString("\nfile: " + f.File)
	b.WriteString("\nsnippet (redacted): " + redact(f.Snippet))
	b.WriteString("\nmessage: " + f.Message)
	return b.String()
}

// parseEnrich parses a model reply into enrichOut. A non-JSON reply is an error,
// not a value: callers must not treat prose as a valid explanation.
func parseEnrich(raw string) (enrichOut, error) {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "{"); i >= 0 {
		if j := strings.LastIndex(raw, "}"); j > i {
			raw = raw[i : j+1]
		}
	}
	var out enrichOut
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return enrichOut{}, fmt.Errorf("ai: respons enrichment bukan JSON valid: %w", err)
	}
	return out, nil
}

// cacheKey identifies an enrichment request. It includes the finding's location
// and message (not just RuleID+Snippet) so distinct findings with identical
// snippets in different files cannot share — and thus swap — a cached answer.
func cacheKey(model string, f model.Finding) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s",
		model, PromptVersion, f.RuleID, f.File, f.Line, f.Message, f.Snippet)))
	return hex.EncodeToString(sum[:])[:24]
}

// defaultAICacheMax bounds each AI cache file so long-lived agent sessions
// cannot grow it without limit (FIFO eviction; mirrors the session cache's
// max_items, PRD §10).
const defaultAICacheMax = 5000

// cache is a tiny JSON-backed key→value store.
type cache struct {
	path  string
	data  map[string]enrichOut
	order []string // FIFO insertion order for bounded eviction
	max   int
	dirty bool
}

func loadCache(dir string) *cache {
	c := &cache{path: filepath.Join(dir, "ai-cache.json"), data: map[string]enrichOut{}, max: defaultAICacheMax}
	if b, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(b, &c.data)
	}
	for k := range c.data {
		c.order = append(c.order, k)
	}
	c.evict()
	return c
}

func (c *cache) get(k string) (enrichOut, bool) {
	v, ok := c.data[k]
	return v, ok
}

func (c *cache) put(k string, v enrichOut) {
	if _, ok := c.data[k]; !ok {
		c.order = append(c.order, k)
		c.dirty = true
	}
	c.data[k] = v
	c.evict()
}

func (c *cache) evict() {
	for c.max > 0 && len(c.data) > c.max && len(c.order) > 0 {
		delete(c.data, c.order[0])
		c.order = c.order[1:]
		c.dirty = true
	}
}

func (c *cache) save() {
	if !c.dirty {
		return
	}
	_ = os.MkdirAll(filepath.Dir(c.path), 0o755)
	if b, err := json.MarshalIndent(c.data, "", "  "); err == nil {
		_ = os.WriteFile(c.path, b, 0o644)
	}
	c.dirty = false
}

// strCache is a tiny JSON-backed key→string store (raw model responses for
// AI-detector mode, keyed by content hash so repeated scans don't pay twice).
type strCache struct {
	path  string
	data  map[string]string
	order []string // FIFO insertion order for bounded eviction
	max   int
	dirty bool
}

func loadStrCache(path string) *strCache {
	c := &strCache{path: path, data: map[string]string{}, max: defaultAICacheMax}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &c.data)
	}
	for k := range c.data {
		c.order = append(c.order, k)
	}
	c.evict()
	return c
}

func (c *strCache) get(k string) (string, bool) {
	v, ok := c.data[k]
	return v, ok
}

func (c *strCache) put(k, v string) {
	if _, ok := c.data[k]; !ok {
		c.order = append(c.order, k)
		c.dirty = true
	}
	c.data[k] = v
	c.evict()
}

func (c *strCache) evict() {
	for c.max > 0 && len(c.data) > c.max && len(c.order) > 0 {
		delete(c.data, c.order[0])
		c.order = c.order[1:]
		c.dirty = true
	}
}

func (c *strCache) save() {
	if !c.dirty {
		return
	}
	_ = os.MkdirAll(filepath.Dir(c.path), 0o755)
	if b, err := json.MarshalIndent(c.data, "", "  "); err == nil {
		_ = os.WriteFile(c.path, b, 0o644)
	}
	c.dirty = false
}

func approxTokens(s string) int { return len(s)/4 + 1 }

// confOr returns the model's confidence clamped to [0,1], or def when the field
// was absent. An explicit 0 is honored (not inflated): "unsure" stays unsure.
func confOr(v *float64, def float64) float64 {
	if v == nil {
		return def
	}
	if *v < 0 {
		return 0
	}
	if *v > 1 {
		return 1
	}
	return *v
}

// redact removes obvious secrets from text before sending it to a provider.
func redact(s string) string {
	out := s
	for _, p := range redactPatterns {
		out = p.re.ReplaceAllString(out, p.repl)
	}
	return out
}
