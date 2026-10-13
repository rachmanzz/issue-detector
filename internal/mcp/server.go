// Package mcp implements an MCP (Model Context Protocol) server for AI coding
// agents (PRD §3.7 / §11 M10). It speaks JSON-RPC 2.0 over newline-delimited
// stdio or HTTP (POST /mcp), exposing the ISO tools:
// scan, get_finding, fix_hint, rules_list, baseline_ignore, trend.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/rachmanzz/issue-detector/internal/baseline"
	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/deps"
	"github.com/rachmanzz/issue-detector/internal/history"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/rules"
	"github.com/rachmanzz/issue-detector/internal/scanner"
	"github.com/rachmanzz/issue-detector/internal/score"
)

// Server holds MCP session state and tool implementations.
type Server struct {
	Root         string
	Config       config.Config
	BaselinePath string
	HistoryPath  string
	Version      string
	Log          *slog.Logger

	mu   sync.Mutex
	last *model.ScanResult
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Handle processes one protocol message and returns the response bytes.
// Notifications return a nil response (caller must not write anything).
func (s *Server) Handle(data []byte) []byte {
	var req request
	if err := json.Unmarshal(data, &req); err != nil {
		return mustJSON(response{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error: " + err.Error()}})
	}
	if req.ID == nil || string(req.ID) == "null" {
		return nil // notification
	}
	if req.Method == "initialize" {
		return mustJSON(response{JSONRPC: "2.0", ID: req.ID, Result: s.toolInfo()})
	}
	if req.Method == "tools/list" {
		return mustJSON(response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": s.toolList()}})
	}
	if req.Method == "tools/call" {
		return s.call(req)
	}
	if req.Method == "ping" {
		return mustJSON(response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})
	}
	return mustJSON(response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}})
}

func (s *Server) call(req request) []byte {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return mustJSON(response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: err.Error()}})
	}
	out, toolErr := s.runTool(context.Background(), params.Name, params.Arguments)
	res := response{JSONRPC: "2.0", ID: req.ID}
	if toolErr != nil {
		res.Error = &rpcError{Code: -32603, Message: toolErr.Error()}
	} else {
		text, _ := json.MarshalIndent(out, "", "  ")
		res.Result = map[string]any{
			"content": []map[string]string{{"type": "text", "text": string(text)}},
		}
	}
	return mustJSON(res)
}

// ToolList describes each tool with its JSON input schema.
func (s *Server) toolList() []map[string]any {
	str := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}
	return []map[string]any{
		{"name": "scan",
			"description": "Pindai root/path dan kembalikan temuan (ScanResult), termasuk CVE OSV dan baseline filter.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"root":     str("path yang dipindai (default: root server)"),
					"baseline": str("path file baseline (filter temuan lama)"),
					"no_git":   map[string]any{"type": "boolean", "description": "lewati analisis git"},
					"no_deps":  map[string]any{"type": "boolean", "description": "lewati CVE/dependency (offline)"},
				},
			}},
		{"name": "get_finding",
			"description": "Cari temuan dari hasil scan terakhir (query teks pada rule/category/title/file).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"query": str("substring filter (kosong = semua)")},
			}},
		{"name": "fix_hint",
			"description": "Ambil saran perbaikan untuk temuan yang cocok dengan query.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"query": str("rule/category/title")},
			}},
		{"name": "rules_list",
			"description": "Daftar semua rule yang tersedia.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "baseline_ignore",
			"description": "Masukkan temuan ke baseline (abaikan di scan berikutnya).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"fingerprint": str("fingerprint temuan (opsional; alternatif: rule_id+file+snippet)"),
					"rule_id":     str("rule id"),
					"file":        str("file path"),
					"snippet":     str("snippet baris"),
				}}},
		{"name": "trend",
			"description": "Snapshot history scan (jika --history dikonfigurasi).",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
	}
}

func (s *Server) toolInfo() map[string]any {
	return map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]string{"name": "issue-detector", "version": s.Version},
	}
}

func (s *Server) runTool(ctx context.Context, name string, args map[string]any) (any, error) {
	arg := func(k string) string {
		if args == nil {
			return ""
		}
		if v, ok := args[k]; ok {
			return fmt.Sprint(v)
		}
		return ""
	}
	switch name {
	case "scan":
		return s.toolScan(ctx, args)
	case "get_finding":
		return s.toolGetFinding(arg("query")), nil
	case "fix_hint":
		return s.toolFixHint(arg("query")), nil
	case "rules_list":
		return ruleTable(), nil
	case "baseline_ignore":
		if err := s.toolBaselineIgnore(args); err != nil {
			return nil, err
		}
		return map[string]string{"status": "ignored"}, nil
	case "trend":
		return s.toolTrend()
	default:
		return nil, fmt.Errorf("tool tidak dikenal: %s", name)
	}
}

func (s *Server) toolScan(ctx context.Context, args map[string]any) (any, error) {
	root := s.Root
	if r, ok := args["root"].(string); ok && r != "" {
		root = r
	}
	cfg := s.Config
	if v, ok := args["no_git"].(bool); ok {
		cfg.NoGit = v
	}
	noDeps := false
	if v, ok := args["no_deps"].(bool); ok {
		noDeps = v
	}
	res, err := scanner.Scan(ctx, scanner.Options{Root: root, Config: cfg})
	if err != nil {
		return nil, err
	}
	if !noDeps && len(res.Dependencies) > 0 {
		if cve, cerr := deps.NewClient().Lookup(ctx, res.Dependencies); cerr == nil && len(cve) > 0 {
			mergeFindings(res, cve)
		}
	}
	if bp, ok := args["baseline"].(string); ok && bp != "" {
		if set, berr := baseline.Load(bp); berr == nil {
			set.Filter(res)
		}
	}
	s.mu.Lock()
	s.last = res
	s.mu.Unlock()
	return res, nil
}

// mergeFindings appends extra findings (CVE) and re-derives summary+score.
func mergeFindings(res *model.ScanResult, extra []model.Finding) {
	res.Findings = append(res.Findings, extra...)
	model.SortFindings(res.Findings)
	score.Apply(res.Findings)
	res.Summary.Findings = len(res.Findings)
	res.Summary.BySeverity = map[model.Severity]int{}
	for _, f := range res.Findings {
		res.Summary.BySeverity[f.Severity]++
	}
}

func (s *Server) toolGetFinding(query string) any {
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	if last == nil {
		return []model.Finding{}
	}
	q := strings.ToLower(query)
	var out []model.Finding
	for _, f := range last.Findings {
		hay := strings.ToLower(f.RuleID + " " + string(f.Category) + " " + f.Title + " " + f.File)
		if q == "" || strings.Contains(hay, q) {
			out = append(out, f)
		}
	}
	return out
}

func (s *Server) toolFixHint(query string) any {
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	if last == nil {
		return map[string]string{"hint": ""}
	}
	q := strings.ToLower(query)
	for _, f := range last.Findings {
		hay := strings.ToLower(f.RuleID + " " + string(f.Category) + " " + f.Title)
		if q == "" || strings.Contains(hay, q) {
			return map[string]string{"rule_id": f.RuleID, "hint": f.FixHint}
		}
	}
	return map[string]string{"hint": ""}
}

func ruleTable() []map[string]any {
	reg := rules.NewRegistry()
	var out []map[string]any
	for _, r := range reg.All() {
		out = append(out, map[string]any{
			"id": r.ID, "category": r.Category, "severity": r.Severity,
			"title": r.Title, "confidence": r.Confidence,
		})
	}
	return out
}

func (s *Server) toolBaselineIgnore(args map[string]any) error {
	fp, _ := args["fingerprint"].(string)
	ruleID, _ := args["rule_id"].(string)
	file, _ := args["file"].(string)
	snippet, _ := args["snippet"].(string)
	if fp == "" {
		fp = baseline.Fingerprint(model.Finding{RuleID: ruleID, File: file, Snippet: snippet})
	}
	path := s.BaselinePath
	if path == "" {
		path = ".issue-detector-baseline.json"
	}
	return baseline.Add(path, []string{fp})
}

func (s *Server) toolTrend() (any, error) {
	if s.HistoryPath == "" {
		return []history.Snapshot{}, nil
	}
	store, err := history.Open(s.HistoryPath)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	return store.Scans(30)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
