package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/history"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/scanner"
	"github.com/spf13/cobra"
)

// DefaultHistoryFile is where watch/trend store their SQLite history.
const DefaultHistoryFile = ".issue-detector-history.db"

func newWatchCmd() *cobra.Command {
	var (
		historyPath string
		interval    time.Duration
		once        bool
		noGit       bool
	)
	cmd := &cobra.Command{
		Use:   "watch [root]",
		Short: "Rescan berkala + simpan snapshot ke history (PRD §11 M7)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			store, err := history.Open(historyPath)
			if err != nil {
				return err
			}
			defer store.Close()

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			cfg := config.Default()
			cfg.NoGit = noGit

			for {
				res, err := scanner.Scan(cmd.Context(), scanner.Options{
					Root: root, Config: cfg, Log: logger,
				})
				if err != nil {
					return err
				}
				if err := store.Record(res); err != nil {
					return err
				}
				writeSummaryLine(os.Stderr, res)
				if once {
					return nil
				}
				select {
				case <-cmd.Context().Done():
					return nil
				case <-time.After(interval):
				}
			}
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&historyPath, "history", DefaultHistoryFile, "path database history (SQLite)")
	fl.DurationVar(&interval, "interval", 30*time.Second, "jeda antar rescan")
	fl.BoolVar(&once, "once", false, "scan sekali lalu keluar")
	fl.BoolVar(&noGit, "no-git", false, "lewati analisis kesehatan git")
	return cmd
}

func newTrendCmd() *cobra.Command {
	var (
		historyPath string
		limit       int
		format      string
	)
	cmd := &cobra.Command{
		Use:   "trend",
		Short: "Laporan tren dari history (PRD §11 M7)",
		RunE: func(_ *cobra.Command, _ []string) error {
			store, err := history.Open(historyPath)
			if err != nil {
				return err
			}
			defer store.Close()
			snaps, err := store.Scans(limit)
			if err != nil {
				return err
			}
			if format == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(snaps)
			}
			return writeTrendTable(snaps)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&historyPath, "history", DefaultHistoryFile, "path database history (SQLite)")
	fl.IntVar(&limit, "limit", 30, "jumlah snapshot terbaru")
	fl.StringVarP(&format, "format", "f", "text", "format: text|json")
	return cmd
}

func writeTrendTable(snaps []history.Snapshot) error {
	if len(snaps) == 0 {
		fmt.Println("history kosong")
		return nil
	}
	fmt.Printf("%-20s %8s %8s %6s %6s %8s\n", "TIME", "FINDINGS", "FILES", "CRIT", "HIGH", "AVGSCORE")
	// Oldest first for a readable timeline.
	for i := len(snaps) - 1; i >= 0; i-- {
		s := snaps[i]
		fmt.Printf("%-20s %8d %8d %6d %6d %8.1f\n",
			s.Time.Format("2006-01-02 15:04:05"), s.Findings, s.Files, s.Critical, s.High, s.AvgScore)
	}
	if len(snaps) >= 2 {
		newest, prev := snaps[0], snaps[1]
		fmt.Printf("\ndelta: findings %+d, high %+d\n",
			newest.Findings-prev.Findings, newest.High-prev.High)
	}
	return nil
}

// recordHistory stores a scan result when a history path is configured.
func recordHistory(path string, res *model.ScanResult) error {
	store, err := history.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.Record(res)
}
