package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestRedact(t *testing.T) {
	in := `password := "hunter2secret" key: AKIAIOSFODNN7EXAMPLE`
	out := redact(in)
	if strings.Contains(out, "hunter2secret") {
		t.Errorf("password not redacted: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected redaction marker: %s", out)
	}
}

func TestParseEnrich(t *testing.T) {
	raw := "here you go:\n```json\n{\"explanation\":\"x\",\"remediation\":\"y\",\"confidence\":0.8}\n```"
	out := parseEnrich(raw)
	if out.Explanation != "x" || out.Remediation != "y" || out.Confidence != 0.8 {
		t.Errorf("bad parse: %+v", out)
	}
	// Non-JSON falls back to the raw text.
	if got := parseEnrich("plain text"); got.Explanation != "plain text" {
		t.Errorf("fallback failed: %+v", got)
	}
}

func TestEnrichOpenAIWithCache(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": `{"explanation":"danger","remediation":"use safe api","confidence":0.9}`}},
			},
		})
	}))
	defer srv.Close()

	enr, err := New(Config{
		Provider: "openai", Model: "test", BaseURL: srv.URL, APIKey: "k",
		CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := &model.ScanResult{
		Findings: []model.Finding{
			{RuleID: "SEC-INJ-001", Severity: model.SeverityHigh, Title: "inj", Message: "m",
				File: "a.go", Line: 1, Snippet: `exec.Command("sh","-c",x)`, Source: model.SourceRule},
			{RuleID: "TODO-001", Severity: model.SeverityInfo, Title: "todo", File: "b.go", Line: 1, Source: model.SourceRule},
		},
		Summary: model.Summary{BySeverity: map[model.Severity]int{}},
	}
	n := enr.Enrich(context.Background(), res)
	if n != 1 {
		t.Fatalf("want 1 enriched (only high), got %d", n)
	}
	var aiCount int
	for _, f := range res.Findings {
		if f.Source == model.SourceAI {
			aiCount++
			if f.RuleID != "SEC-INJ-001:ai" {
				t.Errorf("unexpected AI rule id %s", f.RuleID)
			}
		}
	}
	if aiCount != 1 {
		t.Fatalf("want 1 AI finding, got %d", aiCount)
	}

	// Second run: cache should serve without another HTTP hit.
	enr2, _ := New(Config{Provider: "openai", Model: "test", BaseURL: srv.URL, APIKey: "k", CacheDir: enr.cfg.CacheDir})
	fresh := model.Finding{RuleID: "SEC-INJ-001", Severity: model.SeverityHigh, Title: "inj", Message: "m",
		File: "a.go", Line: 1, Snippet: `exec.Command("sh","-c",x)`, Source: model.SourceRule}
	res2 := &model.ScanResult{Findings: []model.Finding{fresh}, Summary: model.Summary{BySeverity: map[model.Severity]int{}}}
	enr2.Enrich(context.Background(), res2)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("cache miss: server hit %d times, want 1", got)
	}
}

func TestNoKeyFails(t *testing.T) {
	// Tanpa key DAN tanpa base URL (endpoint cloud) → error.
	if _, err := New(Config{Provider: "openai"}); err == nil {
		t.Error("expected error without API key on cloud endpoint")
	}
	// Dengan base_url + model (server lokal OpenAI-compatible) → tidak butuh key.
	if _, err := New(Config{Provider: "openai", BaseURL: "http://localhost:11434/v1", Model: "llama3"}); err != nil {
		t.Errorf("base_url lokal harus boleh tanpa key: %v", err)
	}
}

func TestBaseURLRequiresModel(t *testing.T) {
	// base_url tanpa model → error (jangan pakai default OpenAI).
	if _, err := New(Config{Provider: "openai", BaseURL: "http://localhost:11434/v1"}); err == nil {
		t.Error("base_url tanpa model harus error")
	}
	// base_url + model apa pun (server bebas) → ok.
	if _, err := New(Config{Provider: "openai", BaseURL: "http://localhost:8000/v1", Model: "mistral-7b"}); err != nil {
		t.Errorf("base_url + model harus ok: %v", err)
	}
}
