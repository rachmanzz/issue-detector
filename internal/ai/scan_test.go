package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/model"
)

func TestDetectMapsLinesAndSummary(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		prompt := ""
		if len(req.Messages) > 0 {
			prompt = req.Messages[len(req.Messages)-1].Content
		}
		content := ""
		if strings.Contains(prompt, "STRICT JSON") {
			content = `{"findings":[{"line":1,"severity":"high","category":"security","title":"Hardcoded secret","message":"m","fix":"use env","confidence":0.8}]}`
		} else {
			content = "Perubahan menambah risiko sedang; prioritas: rahasia ter-hardcode."
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": content}}},
		})
	}))
	defer srv.Close()

	e, err := New(Config{Provider: "openai", Model: "m", BaseURL: srv.URL, APIKey: "k", CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	// 400 identical lines → two overlapping chunks (starts 1 and 336).
	content := strings.Repeat("x\n", 399) + "x"
	files := []model.AIFile{{RelPath: "a.go", Content: content, Language: model.LanguageGo}}

	findings, summary, err := e.Detect(context.Background(), files)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (one per chunk), got %d", len(findings))
	}
	if findings[0].Line != 1 || findings[1].Line != 336 {
		t.Errorf("chunk line offsets wrong: %d,%d", findings[0].Line, findings[1].Line)
	}
	for _, f := range findings {
		if f.Source != model.SourceAI {
			t.Errorf("source = %q, want ai", f.Source)
		}
		if f.Severity != model.SeverityHigh {
			t.Errorf("severity = %q", f.Severity)
		}
	}
	if !strings.Contains(summary, "prioritas") {
		t.Errorf("summary not captured: %q", summary)
	}

	// Second run: all chunks + summary served from cache.
	before := atomic.LoadInt32(&hits)
	if _, _, err := e.Detect(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&hits); got != before {
		t.Errorf("cache miss: hits %d -> %d", before, got)
	}
}

// TestDetectRequestFullRepush verifies the partial→full loop: an excerpt prompt
// may ask for the whole file by id, and the detector then repushes the full
// content (proving the model can see content outside the changed excerpt).
func TestDetectRequestFullRepush(t *testing.T) {
	var mu sync.Mutex
	var prompts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		prompt := ""
		if len(req.Messages) > 0 {
			prompt = req.Messages[len(req.Messages)-1].Content
		}
		reply := "ringkasan"
		if strings.Contains(prompt, "STRICT JSON") {
			mu.Lock()
			prompts = append(prompts, prompt)
			mu.Unlock()
			if strings.Contains(prompt, "SECRET_FULL_ONLY") {
				reply = `{"findings":[{"line":40,"severity":"critical","category":"secrets","title":"leak","message":"m","confidence":0.9}]}`
			} else {
				reply = `{"findings":[],"request_full":["a.go#id1"]}`
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": reply}}},
		})
	}))
	defer srv.Close()

	e, err := New(Config{Provider: "openai", Model: "m", BaseURL: srv.URL, APIKey: "k", CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	lines := make([]string, 60)
	for i := range lines {
		lines[i] = "line"
	}
	lines[39] = "SECRET_FULL_ONLY = 1"
	content := strings.Join(lines, "\n")

	files := []model.AIFile{{
		RelPath: "a.go", Content: content, Language: model.LanguageGo, ID: "a.go#id1",
		Ranges: []model.LineRange{{Start: 2, End: 2}},
	}}
	findings, _, err := e.Detect(context.Background(), files)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 || findings[0].Line != 40 || findings[0].Source != model.SourceAI {
		t.Fatalf("repush finding wrong: %+v", findings)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(prompts) < 2 {
		t.Fatalf("want >=2 detect calls (excerpt + repush), got %d", len(prompts))
	}
	sawFull, sawExcerptOnly := false, false
	for _, p := range prompts {
		if strings.Contains(p, "SECRET_FULL_ONLY") {
			sawFull = true
		} else if strings.Contains(p, "EXCERPT") {
			sawExcerptOnly = true
		}
	}
	if !sawFull || !sawExcerptOnly {
		t.Errorf("expected an excerpt-only prompt and a full repush: full=%v excerpt=%v", sawFull, sawExcerptOnly)
	}
}

// TestDetectMalformedJSON verifies an unparseable detector reply surfaces an
// error (so the scan is Incomplete and retried) and is NOT cached as success.
func TestDetectMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": "not json at all"}}},
		})
	}))
	defer srv.Close()
	e, _ := New(Config{Provider: "openai", Model: "m", BaseURL: srv.URL, APIKey: "k", CacheDir: t.TempDir()})
	findings, _, err := e.Detect(context.Background(), []model.AIFile{{RelPath: "a.go", Content: "a\nb"}})
	if err == nil {
		t.Fatalf("malformed JSON must return an error, not silent success")
	}
	if len(findings) != 0 {
		t.Fatalf("want 0 findings, got %d", len(findings))
	}
	// The summarize reply is plain text (cached under a "sum|" key) and that is
	// fine; what must NOT be cached is the unparseable detect reply.
	for k := range e.dcache.data {
		if !strings.HasPrefix(k, "sum|") {
			t.Errorf("unparseable detect reply must not be cached (key %q)", k)
		}
	}
}

// TestExcerptChunksBounded verifies a large changed range is split into bounded
// windows (no long single prompt) and never includes lines outside the range.
func TestExcerptChunksBounded(t *testing.T) {
	lines := make([]string, 1000)
	for i := range lines {
		lines[i] = "line"
	}
	content := strings.Join(lines, "\n")
	// One changed range spanning 900 lines (+ context is clamped to the file).
	chunks := excerptChunks(content, []model.LineRange{{Start: 50, End: 950}})
	if len(chunks) < 2 {
		t.Fatalf("want the range split into multiple chunks, got %d", len(chunks))
	}
	for _, c := range chunks {
		n := strings.Count(c.text, "\n") + 1
		if n > defaultChunkLines {
			t.Errorf("chunk at %d has %d lines, exceeds %d", c.start, n, defaultChunkLines)
		}
		if c.start < 42 || c.start > 950 {
			t.Errorf("chunk start %d outside clamped range [42,950]", c.start)
		}
	}
}

// TestDetectPromptCarriesID guards that every detect prompt still carries the
// file id, so the request-full repush contract keeps working after chunking.
func TestDetectPromptCarriesID(t *testing.T) {
	f := model.AIFile{RelPath: "a/b.go", Language: model.LanguageGo, ID: "a/b.go#deadbeef", Content: "x\ny\n"}
	p := buildDetectPrompt(f, chunk{start: 1, text: "x\ny"}, true)
	if !strings.Contains(p, "a/b.go#deadbeef") {
		t.Errorf("prompt missing file id:\n%s", p)
	}
}

// TestScaleFindingsExcerptMapping verifies line mapping for an excerpt chunk
// whose start is > 1: relative numbering maps correctly, absolute numbering is
// accepted as-is, and a line outside the snippet is dropped (never shown).
func TestScaleFindingsExcerptMapping(t *testing.T) {
	content := strings.Join(make([]string, 100), "\n")
	file := model.AIFile{RelPath: "a.go", Content: content}
	ch := chunk{start: 34, text: strings.Repeat("x\n", 23) + "x"} // 24 lines: 34..57

	raw := []detectFinding{
		{Line: 16, Title: "relative", Severity: "low"}, // snippet line 16 → abs 49
		{Line: 49, Title: "absolute", Severity: "low"}, // already absolute → 49
		{Line: 200, Title: "outside", Severity: "low"}, // beyond snippet → dropped
	}
	got := scaleFindings(file, ch, raw, 10)
	byTitle := map[string]int{}
	for _, f := range got {
		byTitle[f.Title] = f.Line
	}
	if byTitle["relative"] != 49 {
		t.Errorf("relative line: got %d, want 49", byTitle["relative"])
	}
	if byTitle["absolute"] != 49 {
		t.Errorf("absolute line: got %d, want 49", byTitle["absolute"])
	}
	if _, ok := byTitle["outside"]; ok {
		t.Errorf("line outside the sent snippet must be dropped")
	}
}

// TestSummarizeFailureIsNotFatal guards that a failing narrative summary does
// not make the detector report an error (which would mark the scan partial and
// block the session ledger) — detection chunks succeeded.
func TestSummarizeFailureIsNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		prompt := ""
		if len(req.Messages) > 0 {
			prompt = req.Messages[len(req.Messages)-1].Content
		}
		if strings.Contains(prompt, "Ringkas") {
			w.WriteHeader(http.StatusInternalServerError) // summary endpoint fails
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{
				"content": `{"findings":[{"line":1,"severity":"high","category":"bug","title":"t","message":"m","confidence":0.9}]}`,
			}}},
		})
	}))
	defer srv.Close()
	e, _ := New(Config{Provider: "openai", Model: "m", BaseURL: srv.URL, APIKey: "k", CacheDir: t.TempDir()})

	findings, _, err := e.Detect(context.Background(), []model.AIFile{{RelPath: "a.go", Content: "a\nb"}})
	if err != nil {
		t.Fatalf("a summary failure must not error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("detection findings must be kept, got %d", len(findings))
	}
}

func TestChunkContent(t *testing.T) {
	if got := chunkContent(""); got != nil {
		t.Errorf("empty content should yield no chunks, got %d", len(got))
	}
	if got := chunkContent("one\ntwo"); len(got) != 1 || got[0].start != 1 {
		t.Errorf("single chunk expected, got %+v", got)
	}
}
