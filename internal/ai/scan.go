package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// AI-detector mode (PRD §3.2): the model itself identifies issues in the
// changed files, instead of the deterministic rule engine deciding what to send.
const (
	defaultChunkLines = 350
	chunkOverlapLines = 15
	excerptContext    = 8 // lines of context around a changed range
	maxRepushRounds   = 3 // bound the request-full loop
)

// detectFinding is one issue as returned by the model.
type detectFinding struct {
	Line       int      `json:"line"`
	Severity   string   `json:"severity"`
	Category   string   `json:"category"`
	Title      string   `json:"title"`
	Message    string   `json:"message"`
	Fix        string   `json:"fix"`
	Confidence *float64 `json:"confidence"`
}

type detectOut struct {
	Findings []detectFinding `json:"findings"`
	// RequestFull lists file ids whose full content the model needs to judge an
	// excerpt it was shown (the "repush" mechanism).
	RequestFull []string `json:"request_full,omitempty"`
}

type chunk struct {
	start int // 1-based first line within the file
	text  string
}

// Detect runs AI-detector mode over files. Partial files (changed excerpts) are
// sent by default; the model may request the full content of any excerpt via its
// id, which is then repushed on the next round (bounded by maxRepushRounds). It
// returns model findings tagged source=ai plus a short narrative summary.
// Budget/MaxFindings cap cost and volume.
func (e *Enricher) Detect(ctx context.Context, files []model.AIFile) ([]model.Finding, string, error) {
	var findings []model.Finding
	var lastErr error
	byID := make(map[string]model.AIFile, len(files))
	for _, f := range files {
		if f.ID != "" {
			byID[f.ID] = f
		}
	}

	current := files
	sentFull := map[string]bool{}
	for round := 0; round < maxRepushRounds && len(current) > 0; round++ {
		requested := make([]model.AIFile, 0)
		seenReq := map[string]bool{}
		for _, file := range current {
			if e.used >= e.cfg.BudgetTokens || len(findings) >= e.cfg.MaxFindings {
				break
			}
			// Send the whole file when it is new/full or was already repushed;
			// only excerpt payloads may prompt a request-full.
			full := file.Full || len(file.Ranges) == 0 || sentFull[file.ID]
			allowReq := !full
			if full && file.ID != "" {
				sentFull[file.ID] = true
			}
			for _, ch := range detectChunks(file, full) {
				if e.used >= e.cfg.BudgetTokens || len(findings) >= e.cfg.MaxFindings {
					break
				}
				prompt := buildDetectPrompt(file, ch, allowReq, e.cfg.Format)
				cost := approxTokens(prompt)
				if e.used+cost > e.cfg.BudgetTokens {
					break
				}
				out, err := e.cachedDetect(ctx, file, ch, prompt)
				if err != nil {
					lastErr = err
					continue
				}
				e.used += cost
				findings = append(findings, scaleFindings(file, ch, out.Findings, e.cfg.MaxFindings-len(findings))...)
				if !allowReq {
					continue // full payloads are not asked to request more
				}
				for _, id := range out.RequestFull {
					if seenReq[id] || sentFull[id] {
						continue
					}
					if f, ok := byID[id]; ok {
						seenReq[id] = true
						f.Full = true // repush the whole content next round
						requested = append(requested, f)
					}
				}
			}
		}
		current = requested
	}

	findings = dedupFindings(findings)
	// The narrative summary is best-effort: a summarize failure must NOT make
	// the scan look partial (that would block the session ledger forever even
	// though every detection chunk succeeded). Only detection errors propagate.
	summary, _ := e.summarize(ctx, files, findings)
	e.dcache.save()
	return findings, summary, lastErr
}

// detectChunks selects the payload for a file: the whole content, or the changed
// excerpts (with context) when a partial delta is available.
func detectChunks(f model.AIFile, full bool) []chunk {
	if full || len(f.Ranges) == 0 {
		return chunkContent(f.Content)
	}
	return excerptChunks(f.Content, f.Ranges)
}

// excerptChunks builds chunks covering only the changed ranges (+ context). It
// never falls back to sending the whole file: unchanged lines are not sent, so
// the model judges the change set (diff + uncommitted) rather than the file. A
// large changed range is split into bounded windows by chunkRange.
func excerptChunks(content string, ranges []model.LineRange) []chunk {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return nil
	}
	merged := mergeLineRanges(ranges, excerptContext, len(lines))
	var out []chunk
	for _, r := range merged {
		out = append(out, chunkRange(lines, r.Start, r.End)...)
	}
	return out
}

// chunkRange splits lines[start..end] (1-based, inclusive) into bounded,
// overlapping windows so one changed range never becomes a single long prompt.
// Chunks carry only an absolute start offset; the file id stays on the AIFile so
// every chunk in a file shares it and the request-full loop still works.
func chunkRange(lines []string, start, end int) []chunk {
	if len(lines) == 0 {
		return nil
	}
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		return nil
	}
	step := defaultChunkLines - chunkOverlapLines
	if step < 1 {
		step = defaultChunkLines
	}
	var out []chunk
	for s := start; s <= end; s += step {
		e := s + defaultChunkLines - 1
		if e > end {
			e = end
		}
		out = append(out, chunk{start: s, text: strings.Join(lines[s-1:e], "\n")})
		if e == end {
			break
		}
	}
	return out
}

// mergeLineRanges expands each range by ctx lines, clamps to [1,max], sorts and
// coalesces adjacent/overlapping ranges.
func mergeLineRanges(in []model.LineRange, ctx, max int) []model.LineRange {
	if len(in) == 0 || max <= 0 {
		return nil
	}
	rs := make([]model.LineRange, 0, len(in))
	for _, r := range in {
		start, end := r.Start-ctx, r.End+ctx
		if start < 1 {
			start = 1
		}
		if end > max {
			end = max
		}
		if start > end {
			continue
		}
		rs = append(rs, model.LineRange{Start: start, End: end})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Start < rs[j].Start })
	if len(rs) == 0 {
		return nil
	}
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.Start <= last.End+1 {
			if r.End > last.End {
				last.End = r.End
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// scaleFindings converts one chunk's raw findings to model findings, clamped to
// the remaining budget, dropping out-of-range/untitled entries.
func scaleFindings(file model.AIFile, ch chunk, raw []detectFinding, remaining int) []model.Finding {
	lines := strings.Split(file.Content, "\n")
	var out []model.Finding
	for _, df := range raw {
		if len(out) >= remaining {
			break
		}
		title := strings.TrimSpace(df.Title)
		if title == "" {
			continue
		}
		// Map the model's line to the file. The prompt asks for 1-based relative
		// numbering, but relay models sometimes answer with absolute numbers; both
		// are accepted, and anything outside the snippet actually sent is dropped
		// so the model cannot flag lines it never saw.
		n := strings.Count(ch.text, "\n") + 1
		var line int
		switch {
		case df.Line >= 1 && df.Line <= n:
			line = ch.start + df.Line - 1
		case df.Line >= ch.start && df.Line <= ch.start+n-1:
			line = df.Line
		default:
			continue
		}
		if line < 1 || line > len(lines) {
			continue
		}
		snippet := strings.TrimSpace(lines[line-1])
		out = append(out, model.Finding{
			RuleID:     "AI-" + strings.ToUpper(string(normalizeCategory(df.Category))),
			Category:   normalizeCategory(df.Category),
			Severity:   normalizeSeverity(df.Severity),
			Title:      title,
			Message:    strings.TrimSpace(df.Message),
			FixHint:    strings.TrimSpace(df.Fix),
			File:       file.RelPath,
			Line:       line,
			Snippet:    snippet,
			Confidence: confOr(df.Confidence, 0.5),
			Source:     model.SourceAI,
		})
	}
	return out
}

func (e *Enricher) cachedDetect(ctx context.Context, file model.AIFile, ch chunk, prompt string) (detectOut, error) {
	key := detectKey(e.cfg.Model, file.ID, ch.start, ch.text, e.cfg.Format)
	if raw, ok := e.dcache.get(key); ok {
		return parseDetect(raw)
	}
	// jsonMode only for the JSON format: it makes the provider send
	// response_format=json_object (relay models otherwise answer with prose
	// reasoning). The block format is plain text, so jsonMode stays off.
	jsonMode := e.cfg.Format == FormatJSON
	raw, err := e.provider.Complete(ctx, prompt, jsonMode)
	if err != nil {
		return detectOut{}, err
	}
	out, perr := parseDetect(raw)
	if perr != nil {
		// Never cache an unparseable reply: it would masquerade as "no findings"
		// forever. Surfacing the error keeps the scan Incomplete and retried.
		return detectOut{}, perr
	}
	e.dcache.put(key, raw)
	return out, nil
}

// summarize asks for a short narrative of the change set and findings. Failures
// are non-fatal (caller logs); the empty summary simply isn't shown.
func (e *Enricher) summarize(ctx context.Context, files []model.AIFile, findings []model.Finding) (string, error) {
	if len(files) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.WriteString("Ringkas kesehatan perubahan berikut dalam 2-4 kalimat (Bahasa Indonesia) dan sebutkan prioritas utama. Balas teks biasa, tanpa markdown.\n")
	b.WriteString("File berubah:\n")
	for i, f := range files {
		if i >= 50 {
			break
		}
		fmt.Fprintf(&b, "- %s\n", f.RelPath)
	}
	b.WriteString("Temuan:\n")
	if len(findings) == 0 {
		b.WriteString("- (tidak ada temuan)\n")
	}
	for i, fd := range findings {
		if i >= 50 {
			break
		}
		fmt.Fprintf(&b, "- [%s] %s (%s:%d)\n", fd.Severity, fd.Title, fd.File, fd.Line)
	}
	prompt := b.String()
	key := "sum|" + hashStr(e.cfg.Model+"|"+prompt)
	if v, ok := e.dcache.get(key); ok {
		return v, nil
	}
	raw, err := e.provider.Complete(ctx, prompt, false)
	if err != nil {
		return "", err
	}
	txt := strings.TrimSpace(raw)
	e.dcache.put(key, txt)
	return txt, nil
}

// chunkContent splits content into overlapping line windows.
func chunkContent(content string) []chunk {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return nil
	}
	step := defaultChunkLines - chunkOverlapLines
	if step < 1 {
		step = defaultChunkLines
	}
	var out []chunk
	for start := 0; start < len(lines); start += step {
		end := start + defaultChunkLines
		if end > len(lines) {
			end = len(lines)
		}
		out = append(out, chunk{start: start + 1, text: strings.Join(lines[start:end], "\n")})
		if end == len(lines) {
			break
		}
	}
	return out
}

func buildDetectPrompt(f model.AIFile, ch chunk, allowRequest bool, format string) string {
	var b strings.Builder
	b.WriteString("You are a strict senior security and correctness reviewer. Report ONLY issues with concrete, demonstrable impact that a reviewer would block a pull request for.\n")
	b.WriteString("Report: exploitable security vulnerabilities, real correctness bugs, exposed secrets, injection, resource/leaks, and data-loss risks.\n")
	b.WriteString("Do NOT report cosmetic or low-value items: naming, typos, formatting, style, comments/documentation, dead or unused code, code duplication, refactor or \"consider\"/\"prefer\"/\"could\" suggestions, or test-style nits.\n")
	b.WriteString("If an item is only stylistic, speculative, or you are unsure it causes real harm, OMIT it. Do not invent issues. No findings is a valid and common answer.\n")
	b.WriteString("Severity must be low|medium|high|critical (never \"info\"): use \"low\" only for a real, concrete defect — not for a nitpick.\n")
	b.WriteString("Line numbers are 1-based relative to the snippet below (the first line shown is line 1).\n")
	if format == FormatJSON {
		b.WriteString(`Return STRICT JSON only (no markdown): {"findings":[{"line":<int>,"severity":"low|medium|high|critical","category":"security|bug|quality|secrets|dependency|posture|git|todo","title":"...","message":"...","fix":"...","confidence":<0..1>}],"request_full":["<file id>"]}` + "\n")
		if allowRequest {
			fmt.Fprintf(&b, "The snippet is an EXCERPT of changed lines only. If it is insufficient, add the file id%s to request_full to receive the whole file; otherwise omit request_full.\n", fileIDs(f))
		}
	} else {
		b.WriteString("Return findings as PLAIN TEXT blocks, not JSON, no markdown fences. Emit one block per issue and nothing else:\n")
		b.WriteString("[finding]\nline=<int>\nseverity=<low|medium|high|critical>\ncategory=<security|bug|quality|secrets|dependency|posture|git|todo>\nconf=<0..1>\ntitle=<short title>\nmessage=<1-2 sentences>\nfix=<short remediation>\n")
		b.WriteString("Do not quote values and do not add fields beyond those listed. If there are no issues, reply with exactly: (none).\n")
		if allowRequest {
			fmt.Fprintf(&b, "The snippet is an EXCERPT of changed lines only. If it is insufficient, append a block headed [request_full] listing the file id%s, one per line; otherwise omit it.\n", fileIDs(f))
		}
	}
	fmt.Fprintf(&b, "File: %s (id: %s, language: %s)\n", f.RelPath, f.ID, langLabel(f.Language))
	b.WriteString("```\n")
	b.WriteString(redact(ch.text))
	b.WriteString("\n```\n")
	return b.String()
}

// fileIDs renders the file's id as ` ("<id>")` for the request_full hint.
func fileIDs(f model.AIFile) string {
	if f.ID == "" {
		return ""
	}
	return fmt.Sprintf(" %q", f.ID)
}

// parseDetect parses a detector reply. It accepts the JSON format and the
// line-oriented block format (JSON is tried first). An empty reply means "no
// findings". A reply that is neither valid JSON nor a recognizable block is an
// error, never a silent clean result: an unparseable answer means "not
// reviewed", not "clean" — the caller must not advance the checked marker.
func parseDetect(raw string) (detectOut, error) {
	s := stripFences(strings.TrimSpace(raw))
	if s == "" {
		return detectOut{}, nil
	}
	if out, ok := parseDetectJSON(s); ok {
		return out, nil
	}
	if out, ok := parseDetectBlock(s); ok {
		return out, nil
	}
	// Relay models often answer a clean result in prose ("No findings.")
	// instead of an empty block. Accept only an explicit no-findings statement;
	// any other unparseable reply stays an error (so real issues are never
	// silently dropped as "clean").
	if isNoFindings(s) {
		return detectOut{}, nil
	}
	return detectOut{}, fmt.Errorf("ai: respons tak dapat diparse (bukan JSON/blok): %s", truncate(s, 120))
}

// isNoFindings reports whether a reply is an explicit "no issues" statement.
func isNoFindings(s string) bool {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.Trim(t, ".! \t\r\n")
	switch t {
	case "no findings", "no issues", "no problems", "none", "(none)", "n/a", "na",
		"tidak ada temuan", "tidak ada masalah", "tidak ditemukan temuan":
		return true
	}
	return false
}

// stripFences removes an optional ```/```json fence the model may have added.
func stripFences(s string) string {
	if i := strings.Index(s, "```"); i >= 0 {
		s = s[i+3:]
		if j := strings.Index(s, "```"); j >= 0 {
			s = s[:j]
		}
		s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "json"))
	}
	return s
}

// parseDetectJSON parses the JSON detector format. ok=false means the reply is
// not a JSON object (it may still be a valid block reply).
func parseDetectJSON(s string) (detectOut, bool) {
	i := strings.Index(s, "{")
	if i < 0 {
		return detectOut{}, false
	}
	body := s[i:]
	if j := strings.LastIndex(body, "}"); j >= 0 {
		body = body[:j+1]
	}
	var out detectOut
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return detectOut{}, false
	}
	return out, true
}

// parseDetectBlock parses the line-oriented block format:
//
//	[finding]
//	line=12
//	severity=high
//	...
//	[request_full]
//	<file id>
//
// It is deliberately lenient: unknown keys are ignored, a `key=value` seen
// before any header implicitly starts a finding, and a line that is neither a
// header nor a `key=value` is appended to the previous field (so multi-line
// messages survive). Returns ok=false when no block structure is recognized.
func parseDetectBlock(s string) (detectOut, bool) {
	var out detectOut
	var cur *detectFinding
	curField := ""
	inReq := false
	seen := false
	flush := func() {
		if cur != nil {
			out.Findings = append(out.Findings, *cur)
			cur = nil
		}
	}
	for _, rawLine := range strings.Split(s, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if h, isHeader := blockHeader(line); isHeader {
			flush()
			seen = true
			if h == "request_full" {
				inReq = true
			} else {
				inReq = false
				cur = &detectFinding{}
				curField = ""
			}
			continue
		}
		if inReq {
			out.RequestFull = append(out.RequestFull, line)
			continue
		}
		if key, val, ok := splitKeyVal(line); ok {
			if cur == nil {
				cur = &detectFinding{}
			}
			curField = assignDetectField(cur, key, val)
			seen = true
			continue
		}
		if cur != nil && curField != "" {
			appendDetectField(cur, curField, line)
			seen = true
		}
	}
	flush()
	return out, seen
}

// blockHeader reports whether a line is a `[name]` section header and returns
// its normalized name ("finding" or "request_full").
func blockHeader(line string) (string, bool) {
	if len(line) < 3 || line[0] != '[' || line[len(line)-1] != ']' {
		return "", false
	}
	name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
	switch {
	case strings.Contains(name, "request"):
		return "request_full", true
	case strings.Contains(name, "finding") || strings.Contains(name, "issue"):
		return "finding", true
	}
	return "", false
}

// splitKeyVal splits a `key=value` line (trims surrounding spaces).
func splitKeyVal(line string) (key, val string, ok bool) {
	i := strings.Index(line, "=")
	if i <= 0 {
		return "", "", false
	}
	key = strings.ToLower(strings.TrimSpace(line[:i]))
	if key == "" {
		return "", "", false
	}
	return key, strings.TrimSpace(line[i+1:]), true
}

// assignDetectField stores one field and returns its canonical name (used to
// continue multi-line values); an unknown key returns "".
func assignDetectField(f *detectFinding, key, val string) string {
	switch key {
	case "line", "ln", "lineno", "line_number":
		if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
			f.Line = n
		}
		return "line"
	case "severity", "sev":
		f.Severity = val
		return "severity"
	case "category", "cat":
		f.Category = val
		return "category"
	case "title", "name":
		f.Title = val
		return "title"
	case "message", "body", "msg", "description":
		f.Message = val
		return "message"
	case "fix", "fix_hint", "remediation":
		f.Fix = val
		return "fix"
	case "conf", "confidence", "score":
		if v, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil {
			f.Confidence = &v
		}
		return "confidence"
	default:
		return ""
	}
}

func appendDetectField(f *detectFinding, field, extra string) {
	switch field {
	case "title":
		f.Title = strings.TrimSpace(f.Title + " " + extra)
	case "message":
		f.Message = strings.TrimSpace(f.Message + "\n" + extra)
	case "fix":
		f.Fix = strings.TrimSpace(f.Fix + "\n" + extra)
	}
}

func normalizeSeverity(s string) model.Severity {
	sev := model.Severity(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := model.SeverityWeight[sev]; ok {
		return sev
	}
	return model.SeverityMedium
}

func normalizeCategory(s string) model.Category {
	c := model.Category(strings.ToLower(strings.TrimSpace(s)))
	for _, k := range model.AllCategories {
		if k == c {
			return c
		}
	}
	return model.CategoryBug
}

func langLabel(l model.Language) string {
	if l == "" {
		return string(model.LanguageUnknown)
	}
	return string(l)
}

func dedupFindings(fs []model.Finding) []model.Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		key := fmt.Sprintf("%s|%d|%s", f.File, f.Line, strings.ToLower(f.Title))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func detectKey(modelName, id string, start int, text, format string) string {
	return hashStr(fmt.Sprintf("%s|%s|detect|%s|%d|%s|%s", modelName, PromptVersion, id, start, text, format))
}

func hashStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:32]
}
