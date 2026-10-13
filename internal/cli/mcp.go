package cli

import (
	"log/slog"
	"os"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/mcp"
	"github.com/rachmanzz/issue-detector/internal/version"
	"github.com/spf13/cobra"
)

func newMCPCmd() *cobra.Command {
	var (
		root     string
		history  string
		baseline string
		noGit    bool
	)
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Mode MCP server (stdio) untuk AI agent (PRD §3.7)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Default()
			cfg.NoGit = noGit
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			srv := &mcp.Server{
				Root: root, Config: cfg, BaselinePath: baseline, HistoryPath: history,
				Version: version.Version, Log: logger,
			}
			return srv.ServeStdio(cmd.Context(), os.Stdin, os.Stdout)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&root, "root", ".", "root scan default")
	fl.StringVar(&history, "history", ".issue-detector-history.db", "path history SQLite")
	fl.StringVar(&baseline, "baseline", DefaultBaselineFile, "path baseline")
	fl.BoolVar(&noGit, "no-git", false, "lewati analisis kesehatan git")
	return cmd
}
