package cli

import (
	"errors"
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
		host     string
		port     int
		root     string
		history  string
		baseline string
		noGit    bool
		mcpOn    bool
		uiToken  string
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
			cfg := config.Default()
			cfg.NoGit = noGit
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			opts := web.Options{
				Root: root, Config: cfg, HistoryPath: history, BaselinePath: baseline,
				Token: uiToken, Log: logger,
			}
			if mcpOn {
				opts.MCP = &mcp.Server{
					Root: root, Config: cfg, BaselinePath: baseline, HistoryPath: history,
					Version: version.Version,
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
	fl.StringVar(&uiToken, "ui-token", "", "token auth untuk semua endpoint (/api/*, /mcp)")
	return cmd
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
