package cli

import (
	"log/slog"
	"os"

	"github.com/rachmanzz/issue-detector/internal/config"
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
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Mode Web long-running (UI + API) — PRD §3.6",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Default()
			cfg.NoGit = noGit
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			srv := web.New(web.Options{
				Root: root, Config: cfg, HistoryPath: history, BaselinePath: baseline, Log: logger,
			})
			return srv.Listen(host, port)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&host, "host", "127.0.0.1", "alamat bind (default localhost)")
	fl.IntVar(&port, "port", 8088, "port server")
	fl.StringVar(&root, "root", ".", "root scan")
	fl.StringVar(&history, "history", "", "path history SQLite (untuk /api/trend)")
	fl.StringVar(&baseline, "baseline", DefaultBaselineFile, "path baseline (untuk triage)")
	fl.BoolVar(&noGit, "no-git", false, "lewati analisis kesehatan git")
	return cmd
}
