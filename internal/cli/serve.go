package cli

import (
	"log/slog"
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
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Mode Web long-running (UI + API + MCP) — PRD §3.6/§3.7",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Default()
			cfg.NoGit = noGit
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			opts := web.Options{
				Root: root, Config: cfg, HistoryPath: history, BaselinePath: baseline, Log: logger,
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
	return cmd
}
