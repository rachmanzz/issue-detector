package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestDefaultCacheDirGlobal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ISSUE_DETECTOR_HOME", home)
	e, err := New(Config{Provider: "openai", Model: "m", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".issues_detector", "ai-cache")
	if e.cfg.CacheDir != want {
		t.Errorf("CacheDir = %q, want %q", e.cfg.CacheDir, want)
	}
}

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
	out, err := parseEnrich(raw)
	if err != nil {
		t.Fatalf("valid JSON should parse: %v", err)
	}
	if out.Explanation != "x" || out.Remediation != "y" || out.Confidence == nil || *out.Confidence != 0.8 {
		t.Errorf("bad parse: %+v", out)
	}
	// Non-JSON is an error, not a prose "explanation".
	if _, err := parseEnrich("plain text"); err == nil {
		t.Errorf("non-JSON reply must be an error")
	}
	// Absent confidence stays absent (nil), not coerced.
	if out, err := parseEnrich(`{"explanation":"x"}`); err != nil || out.Confidence != nil {
		t.Errorf("absent confidence should be nil: %+v err=%v", out, err)
	}
}

// TestConfOr guards that an explicit confidence of 0 is honored (not inflated)
// and an absent field falls back to the default.
func TestConfOr(t *testing.T) {
	zero, over := 0.0, 1.5
	if got := confOr(&zero, 0.5); got != 0 {
		t.Errorf("explicit 0 must be honored, got %v", got)
	}
	if got := confOr(nil, 0.5); got != 0.5 {
		t.Errorf("absent confidence -> default, got %v", got)
	}
	if got := confOr(&over, 0.5); got != 1 {
		t.Errorf("confidence >1 must clamp to 1, got %v", got)
	}
}

// TestCacheKeyIncludesLocation guards that two findings with identical
// rule+snippet in different files do not share a cache entry.
func TestCacheKeyIncludesLocation(t *testing.T) {
	a := model.Finding{RuleID: "X-1", File: "a.go", Line: 1, Message: "m", Snippet: "s"}
	b := model.Finding{RuleID: "X-1", File: "b.go", Line: 1, Message: "m", Snippet: "s"}
	if cacheKey("m", a) == cacheKey("m", b) {
		t.Errorf("cache key must include the finding's file/location")
	}
}

// TestStrCacheBounded guards that the AI detect cache evicts oldest entries and
// never exceeds its configured maximum.
func TestStrCacheBounded(t *testing.T) {
	c := &strCache{data: map[string]string{}, max: 3}
	for i := 0; i < 5; i++ {
		c.put(fmt.Sprintf("k%d", i), "v")
	}
	if len(c.data) != 3 {
		t.Fatalf("cache must be bounded to 3, got %d", len(c.data))
	}
	if _, ok := c.data["k0"]; ok {
		t.Errorf("oldest entry k0 should have been evicted")
	}
	if _, ok := c.data["k4"]; !ok {
		t.Errorf("newest entry k4 must be present")
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
	n, _ := enr.Enrich(context.Background(), res)
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
	_, _ = enr2.Enrich(context.Background(), res2)
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
