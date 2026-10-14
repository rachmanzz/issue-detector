package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/mcp"
	"github.com/rachmanzz/issue-detector/internal/version"
	"github.com/rachmanzz/issue-detector/internal/web"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var (
		host       string
		port       int
		root       string
		history    string
		baseline   string
		noGit      bool
		mcpOn      bool
		force      bool
		noCache    bool
		uiToken    string
		aiOnly     bool
		aiProvider string
		aiModel    string
		aiBaseURL  string
		aiMax      int
		aiBudget   int
		aiCacheDir string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Mode Web long-running (UI + API + MCP) — PRD §3.6/§3.7",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Reject binding beyond localhost without a token (roast v11).
			if uiToken == "" && !isLoopback(host) {
				return errors.New("serve: bind di luar localhost wajib --ui-token")
			}
			if isLoopback(host) && uiToken == "" {
				slog.Warn("serve: tanpa --ui-token; hanya bind localhost (aman)")
			}

			loaded, _, err := config.LoadProject(root, "")
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			cfg := config.ApplyGlobalCache(loaded)
			if cmd.Flags().Changed("no-git") {
				cfg.NoGit = noGit
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

			// AI config: project `ai:` block + flags. --ai-only makes the web
			// scan use AI as the sole detector (PRD §3.2).
			aiCfg := cfg.AI
			if aiProvider != "" {
				aiCfg.Provider = aiProvider
			}
			if aiModel != "" {
				aiCfg.Model = aiModel
			}
			if aiBaseURL != "" {
				aiCfg.BaseURL = aiBaseURL
			}
			if aiMax > 0 {
				aiCfg.MaxFindings = aiMax
			}
			if aiBudget > 0 {
				aiCfg.BudgetTokens = aiBudget
			}
			if aiCacheDir != "" {
				aiCfg.CacheDir = aiCacheDir
			}
			if aiOnly {
				aiCfg.Only = true
			}

			opts := web.Options{
				Root: root, Config: cfg, HistoryPath: history, BaselinePath: baseline,
				Token: uiToken, Log: logger, Force: force, NoCache: noCache,
			}
			if enr, _, aerr := newEnricher(aiCfg); aiCfg.Enabled || aiCfg.Only {
				if aerr != nil {
					if aiCfg.Only {
						return fmt.Errorf("ai-only: %w", aerr)
					}
					logger.Error("AI diaktifkan tapi dilewati", "err", aerr)
				} else {
					opts.AIOnly = aiCfg.Only
					opts.Detector = enr
				}
			}
			if mcpOn {
				opts.MCP = &mcp.Server{
					Root: root, Config: cfg, BaselinePath: baseline, HistoryPath: history,
					Version: version.Version, Force: force, NoCache: noCache,
				}
			}
			return web.New(opts).Listen(host, port)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&host, "host", "127.0.0.1", "alamat bind (default localhost)")
	fl.IntVar(&port, "port", 8088, "port server")
	fl.StringVar(&root, "root", ".", "root scan")
	fl.StringVar(&history, "history", "", "path history SQLite (untuk /api/trend)")
	fl.StringVar(&baseline, "baseline", DefaultBaselineFile, "path baseline (untuk triage)")
	fl.BoolVar(&noGit, "no-git", false, "lewati analisis kesehatan git")
	fl.BoolVar(&mcpOn, "mcp", false, "ekspos MCP http transport di POST /mcp")
	fl.BoolVar(&force, "force", false, "abaikan hasil cache, paksa scan ulang (tetap refresh cache)")
	fl.BoolVar(&noCache, "no-cache", false, "nonaktifkan cache sesi/hasil")
	fl.StringVar(&uiToken, "ui-token", "", "token auth untuk semua endpoint (/api/*, /mcp)")
	fl.BoolVar(&aiOnly, "ai-only", false, "mode AI-detector: AI menemukan isu sendiri, rule engine dilewati (PRD §3.2)")
	fl.StringVar(&aiProvider, "ai-provider", "", "provider AI: openai|gemini (default config/`openai`)")
	fl.StringVar(&aiModel, "ai-model", "", "nama model AI (default per provider)")
	fl.StringVar(&aiBaseURL, "ai-base-url", "", "override base URL provider AI")
	fl.IntVar(&aiMax, "ai-max-findings", 0, "maksimum temuan AI (default config/25)")
	fl.IntVar(&aiBudget, "ai-budget-tokens", 0, "budget token AI (default config/100000)")
	fl.StringVar(&aiCacheDir, "ai-cache-dir", "", "direktori cache AI (default ~/.issues_detector/ai-cache)")
	return cmd
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
