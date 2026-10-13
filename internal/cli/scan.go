package cli

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rachmanzz/issue-detector/internal/adapter"
	"github.com/rachmanzz/issue-detector/internal/ai"
	"github.com/rachmanzz/issue-detector/internal/baseline"
	"github.com/rachmanzz/issue-detector/internal/config"
	"github.com/rachmanzz/issue-detector/internal/delta"
	"github.com/rachmanzz/issue-detector/internal/deps"
	"github.com/rachmanzz/issue-detector/internal/model"
	"github.com/rachmanzz/issue-detector/internal/pack"
	"github.com/rachmanzz/issue-detector/internal/plugin"
	"github.com/rachmanzz/issue-detector/internal/report"
	"github.com/rachmanzz/issue-detector/internal/rules"
	"github.com/rachmanzz/issue-detector/internal/sbom"
	"github.com/rachmanzz/issue-detector/internal/scanner"
	"github.com/rachmanzz/issue-detector/internal/score"
	"github.com/rachmanzz/issue-detector/internal/sign"
	"github.com/rachmanzz/issue-detector/internal/web"
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
		noDeps      bool
		sbomOut     string
		osvEndpoint string
		adapters    []string
		adapterBox  string
		noAdapters  bool
		aiOn        bool
		aiProvider  string
		aiModel     string
		aiBaseURL   string
		aiMax       int
		aiBudget    int
		aiCacheDir  string
		pluginPaths []string
		packPaths   []string
		requireSig  bool
		keyringPath string
		historyPath string
		webOn       bool
		webPort     int
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

			// Rule packs (PRD §6.5): optionally signature-verified.
			var extraRules []*rules.Rule
			if len(packPaths) > 0 {
				var ring []ed25519.PublicKey
				if keyringPath != "" {
					ring, err = sign.LoadKeyring(keyringPath)
					if err != nil {
						return fmt.Errorf("keyring: %w", err)
					}
				}
				extraRules, err = pack.LoadMany(packPaths, ring, requireSig)
				if err != nil {
					return fmt.Errorf("pack: %w", err)
				}
			}

			res, err := scanner.Scan(cmd.Context(), scanner.Options{
				Root:       root,
				Config:     cfg,
				Filter:     filter,
				Log:        logger,
				Delta:      deltaSet,
				ExtraRules: extraRules,
			})
			if err != nil {
				logger.Error("scan failed", "error", err)
				return exit(report.ExitScanError)
			}

			// CVE lookup for discovered dependencies (PRD §4.6). Network; degrade
			// gracefully when offline.
			if !noDeps && len(res.Dependencies) > 0 {
				client := deps.NewClient()
				if osvEndpoint != "" {
					client.BaseURL = osvEndpoint
				}
				cveFindings, err := client.Lookup(cmd.Context(), res.Dependencies)
				if err != nil {
					logger.Warn("osv lookup gagal; lanjut tanpa CVE", "err", err)
				} else if len(cveFindings) > 0 {
					mergeFindings(res, cveFindings)
				}
			}

			// Optional external adapters (PRD §6.1/§6.2). No-op when absent.
			if !noAdapters {
				af := adapter.Run(cmd.Context(), adapters, adapter.Options{
					Root: root, Sandbox: adapter.Sandbox(adapterBox),
				})
				if len(af) > 0 {
					mergeFindings(res, af)
				}
			}

			// Optional WASM rule plugins (PRD §6.5).
			if len(pluginPaths) > 0 {
				plugins := plugin.Discover(pluginPaths)
				if pf := plugin.Run(cmd.Context(), root, plugins); len(pf) > 0 {
					mergeFindings(res, pf)
				}
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

			// Optional AI enrichment (PRD §6.3 Mode B). Requires an API key.
			if aiOn {
				key := os.Getenv("GEMINI_API_KEY")
				if strings.EqualFold(aiProvider, "openai") || aiProvider == "" {
					key = os.Getenv("OPENAI_API_KEY")
				}
				enr, err := ai.New(ai.Config{
					Provider: aiProvider, Model: aiModel, BaseURL: aiBaseURL, APIKey: key,
					MaxFindings: aiMax, BudgetTokens: aiBudget, CacheDir: aiCacheDir,
				})
				if err != nil {
					logger.Warn("AI enrichment dilewati", "err", err)
				} else if n := enr.Enrich(cmd.Context(), res); n > 0 {
					logger.Info("AI enrichment selesai", "enriched", n)
				}
			}

			// Optional history snapshot for watch/trend (PRD §11 M7).
			if historyPath != "" {
				if err := recordHistory(historyPath, res); err != nil {
					logger.Warn("gagal menyimpan history", "err", err)
				}
			}

			// SBOM export (PRD §4.6).
			if sbomOut != "" {
				sf, err := os.Create(sbomOut)
				if err != nil {
					return fmt.Errorf("sbom: %w", err)
				}
				if err := sbom.Write(sf, res.Tool, res.Root, res.Dependencies); err != nil {
					sf.Close()
					return fmt.Errorf("sbom: %w", err)
				}
				sf.Close()
				logger.Info("sbom ditulis", "file", sbomOut, "packages", len(res.Dependencies))
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
			case "json-lines":
				err = report.WriteJSONLines(w, res)
			case "sarif":
				err = report.WriteSARIF(w, res)
			case "html":
				err = report.WriteHTML(w, res)
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

			// Interactive web layer (PRD §3.6). Blocks until interrupted.
			if webOn {
				srv := web.New(web.Options{
					Root: root, Config: cfg, HistoryPath: historyPath,
					BaselinePath: baselineF, Log: logger,
				})
				logger.Info("web UI", "url", fmt.Sprintf("http://127.0.0.1:%d", webPort))
				return srv.Listen("127.0.0.1", webPort)
			}

			if code := report.ExitFor(res, gate); code != report.ExitOK {
				return exit(code)
			}
			return nil
		},
	}

	fl := cmd.Flags()
	fl.StringVarP(&format, "format", "f", "text", "format output: text|json|json-lines|sarif|html")
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
	fl.BoolVar(&noDeps, "no-deps", false, "lewati pemindaian dependency & CVE (offline)")
	fl.StringVar(&sbomOut, "sbom-out", "", "tulis SBOM (SPDX 2.3 JSON) ke file")
	fl.StringVar(&osvEndpoint, "osv-endpoint", "", "override endpoint OSV API")
	fl.StringArrayVar(&adapters, "adapter", nil, "adapter eksternal (bandit|semgrep|pip-audit; bisa diulang, default semua)")
	fl.StringVar(&adapterBox, "adapter-sandbox", "default", "sandbox adapter: none|default|strict")
	fl.BoolVar(&noAdapters, "no-adapters", false, "lewati adapter eksternal")
	fl.BoolVar(&aiOn, "ai", false, "aktifkan AI enrichment (Mode B); butuh API key env")
	fl.StringVar(&aiProvider, "ai-provider", "openai", "provider AI: openai|gemini")
	fl.StringVar(&aiModel, "ai-model", "", "nama model AI (default per provider)")
	fl.StringVar(&aiBaseURL, "ai-base-url", "", "override base URL provider AI")
	fl.IntVar(&aiMax, "ai-max-findings", 25, "maksimum temuan di-enrich")
	fl.IntVar(&aiBudget, "ai-budget-tokens", 100000, "budget token AI (perkiraan)")
	fl.StringVar(&aiCacheDir, "ai-cache-dir", ".issue-detector-cache", "direktori cache AI")
	fl.StringArrayVar(&pluginPaths, "plugin", nil, "file/direktori plugin WASM (.wasm; bisa diulang)")
	fl.StringArrayVar(&packPaths, "pack", nil, "rule pack (direktori atau .tar.gz; bisa diulang)")
	fl.BoolVar(&requireSig, "require-signature", false, "wajibkan tanda tangan valid untuk pack")
	fl.StringVar(&keyringPath, "pack-keyring", "", "keyring ed25519 (baris base64 public key)")
	fl.StringVar(&historyPath, "history", "", "simpan snapshot ke database history SQLite (PRD §11 M7)")
	fl.BoolVar(&webOn, "web", false, "jalankan Mode Web interaktif setelah scan (PRD §3.6)")
	fl.IntVar(&webPort, "web-port", 8088, "port Mode Web")

	return cmd
}

// mergeFindings appends extra findings (e.g. CVE) and re-derives the summary.
func mergeFindings(res *model.ScanResult, extra []model.Finding) {
	res.Findings = append(res.Findings, extra...)
	model.SortFindings(res.Findings)
	score.Apply(res.Findings)
	res.Summary.Findings = len(res.Findings)
	res.Summary.BySeverity = map[model.Severity]int{}
	for _, f := range res.Findings {
		res.Summary.BySeverity[f.Severity]++
	}
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
	case "text", "json", "json-lines", "sarif", "html":
		return nil
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
