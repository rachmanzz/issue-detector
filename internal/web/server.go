// Package web serves the optional interactive UI and JSON API (PRD §3.6 Mode
// Web). It reuses the same scan engine as the CLI; the UI is embedded and binds
// to localhost by default with an Origin guard and security headers.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/gofiber/fiber/v3"

	"github.com/rachmanzz/issue-detector/internal/baseline"
	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/history"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/rules"
	"github.com/rachmanzz/issue-detector/internal/scanner"
)

// Options configures the web server.
type Options struct {
	Root         string
	Config       config.Config
	HistoryPath  string
	BaselinePath string
	Log          *slog.Logger
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

	app.Get("/", s.handleIndex)
	app.Get("/api/scan", s.handleScan)
	app.Get("/api/events", s.handleEvents)
	app.Get("/api/rules", s.handleRules)
	app.Get("/api/trend", s.handleTrend)
	app.Post("/api/triage", s.handleTriage)
	app.Post("/api/rules/test", s.handleRuleLab)

	return app
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
		"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
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

func (s *Server) scan(ctx context.Context, onProgress func(scanner.Progress)) (*model.ScanResult, error) {
	res, err := scanner.Scan(ctx, scanner.Options{
		Root:       s.opts.Root,
		Config:     s.opts.Config,
		Log:        s.log,
		OnProgress: onProgress,
	})
	if err != nil {
		return nil, err
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

func (s *Server) handleScan(c fiber.Ctx) error {
	res, err := s.scan(c.Context(), nil)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	res.Findings = filterFindings(res.Findings, c)
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
		})
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
func filterFindings(fs []model.Finding, c fiber.Ctx) []model.Finding {
	sevMin := model.SeverityWeight[model.Severity(c.Query("severity_min"))]
	category := model.Category(c.Query("category"))
	source := model.Source(c.Query("source"))
	inDiffOnly := c.Query("in_diff") == "1" || c.Query("in_diff") == "true"

	out := fs[:0]
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
