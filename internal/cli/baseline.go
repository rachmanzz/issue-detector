package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/rachmanzz/issue-detector/internal/baseline"
	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/scanner"
	"github.com/spf13/cobra"
)

// DefaultBaselineFile is where baselines are written/read unless overridden.
const DefaultBaselineFile = ".issue-detector-baseline.json"

func newBaselineCmd() *cobra.Command {
	var (
		output     string
		ignore     []string
		noGit      bool
		noDeps     bool
		noAdapters bool
	)
	cmd := &cobra.Command{
		Use:   "baseline [root]",
		Short: "Tulis baseline dari hasil scan (untuk suppress temuan lama)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			cfg := config.Default()
			cfg.NoGit = noGit
			cfg.Ignore = append(cfg.Ignore, ignore...)
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			res, err := scanner.Scan(cmd.Context(), scanner.Options{
				Root:   root,
				Config: cfg,
				Log:    logger,
			})
			if err != nil {
				return err
			}
			if err := baseline.Save(output, res); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "baseline: %d findings → %s\n", len(res.Findings), output)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&output, "output", "o", DefaultBaselineFile, "path file baseline")
	fl.StringArrayVar(&ignore, "ignore", nil, "pola ignore tambahan (globs)")
	fl.BoolVar(&noGit, "no-git", false, "lewati analisis kesehatan git")
	fl.BoolVar(&noDeps, "no-deps", false, "lewati pemindaian dependency & CVE")
	fl.BoolVar(&noAdapters, "no-adapters", false, "lewati adapter eksternal")
	return cmd
}
