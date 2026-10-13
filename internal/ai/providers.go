package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// Provider completes a single prompt and returns the raw text response.
type Provider interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

func newProvider(cfg Config) (Provider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("ai: API key kosong")
	}
	client := &http.Client{Timeout: 60 * time.Second}
	switch cfg.Provider {
	case "openai", "":
		base := cfg.BaseURL
		if base == "" {
			base = "https://api.openai.com/v1"
		}
		model := cfg.Model
		if model == "" {
			model = "gpt-4o-mini"
		}
		return &openaiProvider{http: client, base: base, model: model, key: cfg.APIKey}, nil
	case "gemini":
		base := cfg.BaseURL
		if base == "" {
			base = "https://generativelanguage.googleapis.com"
		}
		model := cfg.Model
		if model == "" {
			model = "gemini-1.5-flash"
		}
		return &geminiProvider{http: client, base: base, model: model, key: cfg.APIKey}, nil
	default:
		return nil, fmt.Errorf("ai: provider tidak dikenal %q", cfg.Provider)
	}
}

type openaiProvider struct {
	http  *http.Client
	base  string
	model string
	key   string
}

func (p *openaiProvider) Complete(ctx context.Context, prompt string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model": p.model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.key)
	resp, err := p.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai: %s: %s", resp.Status, truncate(string(data), 200))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("openai: empty choices")
	}
	return out.Choices[0].Message.Content, nil
}

type geminiProvider struct {
	http  *http.Client
	base  string
	model string
	key   string
}

func (p *geminiProvider) Complete(ctx context.Context, prompt string) (string, error) {
	url := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s", p.base, p.model, p.key)
	body, _ := json.Marshal(map[string]any{
		"contents": []map[string]any{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]any{"temperature": 0},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini: %s: %s", resp.Status, truncate(string(data), 200))
	}
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if len(out.Candidates) == 0 || len(out.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini: empty candidates")
	}
	return out.Candidates[0].Content.Parts[0].Text, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// redactPatterns keep secrets out of prompts (PRD §6.3 safeguards).
var redactPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// key = value: keep the prefix, drop the value.
	{regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[:=]=?\s*["']?)[^\s"',]{4,}`), "${1}[REDACTED]"},
	// opaque tokens: redact the whole match.
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "[REDACTED]"},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "[REDACTED]"},
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), "[REDACTED]"},
}
