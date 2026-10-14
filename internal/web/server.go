// Package web serves the optional interactive UI and JSON API (PRD §3.6 Mode
// Web). It reuses the same scan engine as the CLI; the UI is embedded and binds
// to localhost by default with an Origin guard and security headers.
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/gofiber/fiber/v3"

	"github.com/rachmanzz/issue-detector/internal/baseline"
	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/history"
	"github.com/rachmanzz/issue-detector/internal/mcp"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/rules"
	"github.com/rachmanzz/issue-detector/internal/scanner"
	"github.com/rachmanzz/issue-detector/internal/scanrun"
	"github.com/rachmanzz/issue-detector/internal/version"
)

// Options configures the web server.
type Options struct {
	Root         string
	Config       config.Config
	HistoryPath  string
	BaselinePath string
	Log          *slog.Logger
	// Token, when set, requires "Authorization: Bearer <token>" on every /api/* and /mcp
	// endpoint — mandatory in practice when binding beyond localhost (roast v11).
	Token string
	// MCP, when set, exposes POST /mcp (MCP http transport, PRD §3.7).
	MCP *mcp.Server
	// AIOnly makes the web scan run AI-detector mode; Detector must be non-nil
	// when set (PRD §3.2).
	AIOnly   bool
	Detector scanner.AIDetector
	// Force bypasses serving a cached result (still refreshes it); NoCache
	// disables the session/result cache entirely (PRD §10).
	Force   bool
	NoCache bool
}

// Server holds shared state for the web layer.
type Server struct {
	opts Options
	log  *slog.Logger
	mu   sync.Mutex
	last *model.ScanResult
}

// New builds a Server.
func New(opts Options) *Server {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	return &Server{opts: opts, log: log}
}

// App assembles the Fiber app with routes, guard and security headers.
func (s *Server) App() *fiber.App {
	app := fiber.New(fiber.Config{
		AppName: "issue-detector-web",
	})

	app.Use(s.securityHeaders)
	app.Use(s.originGuard)

	// Liveness/readiness probes are registered before authGuard so orchestrators
	// (k8s) can probe without a token (PRD §3.6 ops).
	app.Get("/healthz", s.handleHealth)
	app.Get("/readyz", s.handleReady)

	app.Use(s.authGuard)

	app.Get("/", s.handleIndex)
	app.Get("/static/app.js", s.handleAppJS)
	app.Get("/api/scan", s.handleScan)
	app.Get("/api/events", s.handleEvents)
	app.Get("/api/rules", s.handleRules)
	app.Get("/api/trend", s.handleTrend)
	app.Post("/api/triage", s.handleTriage)
	app.Post("/api/rules/test", s.handleRuleLab)
	if s.opts.MCP != nil {
		app.Post("/mcp", s.handleMCP)
	}

	return app
}

// handleMCP adapts the underlying http.Handler to a Fiber route.
func (s *Server) handleMCP(c fiber.Ctx) error {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(c.Body()))
	req.Header.Set("Content-Type", "application/json")
	s.opts.MCP.ServeHTTP(rec, req)
	c.Status(rec.Code)
	return c.Send(rec.Body.Bytes())
}

// Listen serves on the given host:port (blocking).
func (s *Server) Listen(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	s.log.Info("web server listening", "addr", addr, "root", s.opts.Root)
	return s.App().Listen(addr)
}

func (s *Server) securityHeaders(c fiber.Ctx) error {
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	c.Set("Referrer-Policy", "no-referrer")
	return c.Next()
}

// originGuard blocks cross-site requests (anti-CSRF) for non-GET methods and
// API reads when a foreign Origin is present (PRD §3.6 security).
func (s *Server) originGuard(c fiber.Ctx) error {
	origin := c.Get("Origin")
	if origin == "" {
		return c.Next()
	}
	host := c.Hostname()
	allowed := []string{"http://" + host, "https://" + host, "http://localhost", "http://127.0.0.1"}
	for _, a := range allowed {
		if origin == a || strings.HasPrefix(origin, a+":") {
			return c.Next()
		}
	}
	return fiber.NewError(fiber.StatusForbidden, "origin tidak diizinkan")
}

// authGuard requires a bearer token for every endpoint when configured.
func (s *Server) authGuard(c fiber.Ctx) error {
	if s.opts.Token == "" {
		return c.Next()
	}
	const prefix = "Bearer "
	auth := c.Get("Authorization")
	if strings.HasPrefix(auth, prefix) && strings.TrimSpace(auth[len(prefix):]) == s.opts.Token {
		return c.Next()
	}
	return fiber.NewError(fiber.StatusUnauthorized, "token tidak valid")
}

func (s *Server) scan(ctx context.Context, onProgress func(scanner.Progress), force bool) (*model.ScanResult, error) {
	// Share the CLI's cache semantics (PRD §10): serve an unchanged cached
	// result and run AI-only scans incrementally from the last checked commit.
	prep := scanrun.Prepare(ctx, scanrun.Options{
		Root:       s.opts.Root,
		Config:     s.opts.Config,
		Log:        s.log,
		AIOnly:     s.opts.AIOnly,
		Detector:   s.opts.Detector,
		AIEnabled:  s.opts.Config.AI.Enabled,
		OnProgress: onProgress,
		Force:      force || s.opts.Force,
		NoCache:    s.opts.NoCache,
		Version:    version.Version,
	})

	res := prep.Cached
	if res == nil {
		var err error
		res, err = scanner.Scan(ctx, scanner.Options{
			Root:       s.opts.Root,
			Config:     s.opts.Config,
			Log:        s.log,
			OnProgress: onProgress,
			Delta:      prep.Delta,
			AIOnly:     s.opts.AIOnly,
			Detector:   s.opts.Detector,
		})
		if err != nil {
			return nil, err
		}
		prep.Result(res)
	}
	s.mu.Lock()
	s.last = res
	s.mu.Unlock()
	return res, nil
}

func (s *Server) handleIndex(c fiber.Ctx) error {
	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.SendString(indexHTML)
}

func (s *Server) handleAppJS(c fiber.Ctx) error {
	c.Set("Content-Type", "application/javascript; charset=utf-8")
	return c.SendString(appJS)
}

// handleHealth is a liveness probe: the process is up (no auth, no dependencies).
func (s *Server) handleHealth(c fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok"})
}

// handleReady is a readiness probe: dependencies needed to serve are usable.
// The history DB is the only optional external state; when configured it must
// open, otherwise a scan would fail. It is not created here (read-only check).
func (s *Server) handleReady(c fiber.Ctx) error {
	if s.opts.HistoryPath != "" {
		store, err := history.Open(s.opts.HistoryPath)
		if err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"status": "unavailable", "reason": "history: " + err.Error(),
			})
		}
		_ = store.Close()
	}
	return c.JSON(fiber.Map{"status": "ready", "root": s.opts.Root})
}

func (s *Server) handleScan(c fiber.Ctx) error {
	// ?force=1 (or --force at startup) bypasses serving a cached result.
	force := c.Query("force") == "1" || c.Query("force") == "true"
	res, err := s.scan(c.Context(), nil, force)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	res.Findings = filterFindings(res.Findings, c)
	status := res.Status
	if status == "" {
		status = model.StatusComplete
	}
	c.Set("X-Scan-Status", status)
	return c.JSON(res)
}

func (s *Server) handleEvents(c fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		emit := func(event string, data any) {
			b, _ := json.Marshal(data)
			fmt.Fprintf(pw, "event: %s\ndata: %s\n\n", event, b)
		}
		emit("start", map[string]any{"root": s.opts.Root})
		res, err := s.scan(c.Context(), func(p scanner.Progress) {
			emit("progress", map[string]any{"scanned": p.Scanned, "total": p.Total})
		}, false)
		if err != nil {
			emit("error", map[string]any{"error": err.Error()})
			return
		}
		emit("result", res)
		emit("done", map[string]any{"findings": res.Summary.Findings})
	}()
	return c.SendStream(pr)
}

func (s *Server) handleRules(c fiber.Ctx) error {
	return c.JSON(fiber.Map{"rules": ruleSummaries()})
}

func (s *Server) handleTrend(c fiber.Ctx) error {
	if s.opts.HistoryPath == "" {
		return c.JSON([]history.Snapshot{})
	}
	store, err := history.Open(s.opts.HistoryPath)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	defer store.Close()
	snaps, err := store.Scans(50)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.JSON(snaps)
}

func (s *Server) handleTriage(c fiber.Ctx) error {
	var body struct {
		Fingerprint string `json:"fingerprint"`
		RuleID      string `json:"rule_id"`
		File        string `json:"file"`
		Snippet     string `json:"snippet"`
	}
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "body tidak valid")
	}
	fp := body.Fingerprint
	if fp == "" {
		fp = baseline.Fingerprint(model.Finding{RuleID: body.RuleID, File: body.File, Snippet: body.Snippet})
	}
	if s.opts.BaselinePath == "" {
		return c.JSON(fiber.Map{"accepted": true, "persisted": false, "fingerprint": fp})
	}
	if err := baseline.Add(s.opts.BaselinePath, []string{fp}); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	return c.JSON(fiber.Map{"accepted": true, "persisted": true, "fingerprint": fp})
}

// handleRuleLab tests a rule YAML against a code snippet live (PRD §3.6 #7
// rule lab). Rule is not persisted.
func (s *Server) handleRuleLab(c fiber.Ctx) error {
	var body struct {
		YAML     string `json:"yaml"`
		Language string `json:"language"`
		Code     string `json:"code"`
	}
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "body tidak valid")
	}
	rule, err := rules.ParseRule([]byte(body.YAML))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	f := &model.File{
		RelPath: "lab", Language: rules.Language(body.Language),
		Lines: strings.Split(body.Code, "\n"),
	}
	matches, err := rule.Matcher.Match(c.Context(), f)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return c.JSON(fiber.Map{
		"rule_id": rule.ID, "severity": rule.Severity, "matches": matches,
	})
}

// filterFindings applies query filters: severity_min, category, source, in_diff.
// Pure: never mutates the input slice (must not corrupt the stored last result).
func filterFindings(fs []model.Finding, c fiber.Ctx) []model.Finding {
	sevMin := model.SeverityWeight[model.Severity(c.Query("severity_min"))]
	category := model.Category(c.Query("category"))
	source := model.Source(c.Query("source"))
	inDiffOnly := c.Query("in_diff") == "1" || c.Query("in_diff") == "true"

	out := make([]model.Finding, 0, len(fs))
	for _, f := range fs {
		if sevMin > 0 && model.SeverityWeight[f.Severity] < sevMin {
			continue
		}
		if category != "" && f.Category != category {
			continue
		}
		if source != "" && f.Source != source {
			continue
		}
		if inDiffOnly && !f.InDiff {
			continue
		}
		out = append(out, f)
	}
	return out
}
