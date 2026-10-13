package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rachmanzz/issue-detector/internal/baseline"
	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/delta"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/report"
	"github.com/rachmanzz/issue-detector/internal/scanner"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		format      string
		output      string
		categories  string
		severityMin string
		failOn      string
		cfgPath     string
		remote      string
		jobs        int
		subWorker   int
		maxFileSize int64
		timeoutSecs int
		quiet       bool
		ignore      []string
		baseRef     string
		diffFile    string
		noGit       bool
		rulesPath   []string
		baselineF   string
	)

	cmd := &cobra.Command{
		Use:   "scan [root]",
		Short: "Scan source / repo (PRD M0)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}

			cfg := config.Default()
			if cfgPath == "" {
				auto := filepath.Join(root, config.FileName)
				if _, err := os.Stat(auto); err == nil {
					cfgPath = auto
				}
			}
			loaded, err := config.Load(cfgPath, cfgPath != "")
			if err != nil {
				return fmt.Errorf("config: %w", err)
			}
			cfg = loaded

			if remote != "" {
				cfg.Remote = remote
			}
			if jobs > 0 {
				cfg.Jobs = jobs
			}
			if subWorker > 0 {
				cfg.SubWorker = subWorker
			}
			if maxFileSize > 0 {
				cfg.MaxFileSize = maxFileSize
			}
			if timeoutSecs > 0 {
				cfg.Timeout = time.Duration(timeoutSecs) * time.Second
			}
			if len(ignore) > 0 {
				cfg.Ignore = ignore
			}
			cfg.NoGit = noGit
			if len(rulesPath) > 0 {
				cfg.Rules = append(cfg.Rules, rulesPath...)
			}

			filter := model.Filter{}
			if categories != "" {
				cats, err := parseCategories(categories)
				if err != nil {
					return err
				}
				filter.Categories = cats
			}
			if severityMin != "" {
				s, err := parseSeverity(severityMin)
				if err != nil {
					return err
				}
				filter.SeverityMin = s
			}
			if failOn == "" {
				failOn = cfg.FailOn
			}
			gate, err := parseSeverity(failOn)
			if err != nil {
				return err
			}

			if err := validateFormat(format); err != nil {
				return err
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: slogLevel(quiet),
			}))

			// Delta scan (PRD §3.4): restrict findings to changed lines.
			var deltaSet *delta.Set
			switch {
			case diffFile != "":
				ds, err := delta.FromPatchFile(diffFile)
				if err != nil {
					return fmt.Errorf("diff: %w", err)
				}
				deltaSet = ds
			case baseRef != "":
				ds, err := delta.FromBase(cmd.Context(), root, baseRef)
				if err != nil {
					return fmt.Errorf("base: %w", err)
				}
				deltaSet = ds
			}

			res, err := scanner.Scan(cmd.Context(), scanner.Options{
				Root:   root,
				Config: cfg,
				Filter: filter,
				Log:    logger,
				Delta:  deltaSet,
			})
			if err != nil {
				logger.Error("scan failed", "error", err)
				return exit(report.ExitScanError)
			}

			// Baseline: suppress findings already accepted (PRD §11 M3).
			if baselineF != "" {
				set, err := baseline.Load(baselineF)
				if err != nil {
					return fmt.Errorf("baseline: %w", err)
				}
				if n := set.Filter(res); n > 0 {
					logger.Info("baseline suppressed findings", "count", n, "file", baselineF)
				}
			}

			w := os.Stdout
			var f *os.File
			if output != "" {
				f, err = os.Create(output)
				if err != nil {
					return fmt.Errorf("output: %w", err)
				}
				defer f.Close()
				w = f
			}

			switch format {
			case "json":
				err = report.WriteJSON(w, res)
			case "sarif":
				err = report.WriteSARIF(w, res)
			default:
				if err := report.WriteText(w, res); err != nil {
					return err
				}
			}
			if err != nil {
				return err
			}

			if !quiet && output == "" {
				writeSummaryLine(os.Stderr, res)
			}

			if code := report.ExitFor(res, gate); code != report.ExitOK {
				return exit(code)
			}
			return nil
		},
	}

	fl := cmd.Flags()
	fl.StringVarP(&format, "format", "f", "text", "format output: text|json|sarif")
	fl.StringVarP(&output, "output", "o", "", "write report ke file (default stdout)")
	fl.StringVar(&categories, "categories", "", "kategori dipisah koma (default semua)")
	fl.StringVar(&severityMin, "severity-min", "", "severity minimum dilaporkan: low|medium|high|critical")
	fl.StringVar(&failOn, "fail-on", "", "gate exit code: none|low|medium|high|critical")
	fl.StringVar(&cfgPath, "config", "", "path config YAML (default <root>/"+config.FileName+")")
	fl.StringVar(&remote, "remote", "", "clone git URL terlebih dahulu, scan di cache dir (root dipakai sebagai cache dir)")
	fl.IntVar(&jobs, "jobs", 0, "jumlah worker (default NumCPU)")
	fl.IntVar(&subWorker, "sub-worker-limit", 0, "fan-out sub-worker per file (default 5)")
	fl.Int64Var(&maxFileSize, "max-file-size", 0, "batas ukuran file (bytes, default 1MB)")
	fl.IntVar(&timeoutSecs, "timeout", 0, "batas durasi scan (detik)")
	fl.BoolVarP(&quiet, "quiet", "q", false, "minimalkan log ke stderr")
	fl.StringArrayVar(&ignore, "ignore", nil, "pola ignore tambahan (globs)")
	fl.StringVar(&baseRef, "base", "", "delta scan: hanya baris berubah sejak ref (branch/tag/commit)")
	fl.StringVar(&diffFile, "diff", "", "delta scan: dari file patch (.diff/.patch)")
	fl.BoolVar(&noGit, "no-git", false, "lewati analisis kesehatan git")
	fl.StringArrayVar(&rulesPath, "rules", nil, "file/direktori rule YAML tambahan (PRD §8)")
	fl.StringVar(&baselineF, "baseline", "", "abaikan temuan yang ada di file baseline (PRD §11 M3)")

	return cmd
}

func parseCategories(s string) (map[model.Category]bool, error) {
	out := map[model.Category]bool{}
	for _, raw := range strings.Split(s, ",") {
		c := model.Category(strings.TrimSpace(strings.ToLower(raw)))
		if !isKnownCategory(c) {
			return nil, fmt.Errorf("kategori tidak dikenal: %q", raw)
		}
		out[c] = true
	}
	return out, nil
}

func isKnownCategory(c model.Category) bool {
	for _, k := range model.AllCategories {
		if k == c {
			return true
		}
	}
	return false
}

func parseSeverity(s string) (model.Severity, error) {
	if s == "" || s == "none" {
		return model.SeverityInfo, nil
	}
	sev := model.Severity(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := model.SeverityWeight[sev]; !ok {
		return "", fmt.Errorf("severity tidak dikenal: %q", s)
	}
	return sev, nil
}

func validateFormat(f string) error {
	switch f {
	case "text", "json", "sarif":
		return nil
	case "html":
		return errors.New("format html akan hadir di M4 (roadmap)")
	default:
		return fmt.Errorf("format tidak dikenal: %q", f)
	}
}

func slogLevel(quiet bool) slog.Level {
	if quiet {
		return slog.LevelError
	}
	return slog.LevelInfo
}

func writeSummaryLine(w *os.File, res *model.ScanResult) {
	fmt.Fprintf(w, "scan %s: %d findings, %d files\n",
		res.ScanID[:min(8, len(res.ScanID))], res.Summary.Findings, res.Summary.FilesEnumerated)
}
