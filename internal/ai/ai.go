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

	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/score"
)

// PromptVersion bumps when the prompt/response contract changes (cache key).
const PromptVersion = "1"

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

// Enricher performs AI enrichment with redaction, cache and budget.
type Enricher struct {
	cfg      Config
	provider Provider
	cache    *cache
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
		cfg.CacheDir = ".issue-detector-cache"
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
	return &Enricher{cfg: cfg, provider: p, cache: loadCache(cfg.CacheDir)}, nil
}

type enrichOut struct {
	Explanation string  `json:"explanation"`
	Remediation string  `json:"remediation"`
	Confidence  float64 `json:"confidence"`
}

// Enrich augments high/critical findings with AI explanation + remediation.
// It returns the number of findings enriched. Errors per-finding are skipped.
func (e *Enricher) Enrich(ctx context.Context, res *model.ScanResult) int {
	enriched := 0
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
	return enriched
}

func (e *Enricher) cached(ctx context.Context, f model.Finding, prompt string) (enrichOut, error) {
	key := cacheKey(e.cfg.Model, f)
	if out, ok := e.cache.get(key); ok {
		return out, nil
	}
	raw, err := e.provider.Complete(ctx, prompt)
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
