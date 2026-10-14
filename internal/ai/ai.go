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
const PromptVersion = "5"

// Config configures enrichment.
type Config struct {
	Provider     string // openai | gemini
	Model        string
	BaseURL      string
	APIKey       string
	MaxFindings  int // cap findings to enrich
	BudgetTokens int // approx token budget across the run
	CacheDir     string
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
	if cfg.CacheDir == "" {
		// Default to the per-user dir so nothing is written into the scanned
		// project. Falls back to a local name if the home dir is unavailable.
		if p, err := config.GlobalPath("ai-cache"); err == nil {
			cfg.CacheDir = p
		} else {
			cfg.CacheDir = ".issue-detector-cache"
		}
	}
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
	Explanation string  `json:"explanation"`
	Remediation string  `json:"remediation"`
	Confidence  float64 `json:"confidence"`
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
			Snippet: f.Snippet, Confidence: clamp01(out.Confidence), Source: model.SourceAI,
		}
		added = append(added, af)
		enriched++
	}
	if len(added) > 0 {
		res.Findings = append(res.Findings, added...)
		model.SortFindings(res.Findings)
		score.Apply(res.Findings)
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
	out := parseEnrich(raw)
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

func parseEnrich(raw string) enrichOut {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "{"); i >= 0 {
		if j := strings.LastIndex(raw, "}"); j > i {
			raw = raw[i : j+1]
		}
	}
	var out enrichOut
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		out.Explanation = strings.TrimSpace(raw)
	}
	return out
}

func cacheKey(model string, f model.Finding) string {
	sum := sha256.Sum256([]byte(model + "|" + PromptVersion + "|" + f.RuleID + "|" + f.Snippet))
	return hex.EncodeToString(sum[:])[:24]
}

// cache is a tiny JSON-backed key→value store.
type cache struct {
	path  string
	data  map[string]enrichOut
	dirty bool
}

func loadCache(dir string) *cache {
	c := &cache{path: filepath.Join(dir, "ai-cache.json"), data: map[string]enrichOut{}}
	if b, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(b, &c.data)
	}
	return c
}

func (c *cache) get(k string) (enrichOut, bool) {
	v, ok := c.data[k]
	return v, ok
}

func (c *cache) put(k string, v enrichOut) {
	if _, ok := c.data[k]; !ok {
		c.dirty = true
	}
	c.data[k] = v
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
	dirty bool
}

func loadStrCache(path string) *strCache {
	c := &strCache{path: path, data: map[string]string{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &c.data)
	}
	return c
}

func (c *strCache) get(k string) (string, bool) {
	v, ok := c.data[k]
	return v, ok
}

func (c *strCache) put(k, v string) {
	if _, ok := c.data[k]; !ok {
		c.dirty = true
	}
	c.data[k] = v
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

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	if v == 0 {
		return 0.6
	}
	return v
}

// redact removes obvious secrets from text before sending it to a provider.
func redact(s string) string {
	out := s
	for _, p := range redactPatterns {
		out = p.re.ReplaceAllString(out, p.repl)
	}
	return out
}
