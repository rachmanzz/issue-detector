// Package config loads scan options from a YAML file with sensible defaults
// (PRD §7 `--config`). Flags passed by the CLI override file values.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rachmanzz/issue-detector/internal/score"
)

// Project config filenames resolved at the scan root. YAML always wins over
// JSON: only the single highest-precedence file is used and the rest are ignored
// (PRD §7.2). A project only needs one of them. JSON is an optional convenience
// mirror of the same schema; the same loader reads either.
const (
	FileName     = "issue-detector.yaml" // canonical YAML config (highest precedence)
	FileNameJSON = "issue-detector.json" // JSON config (lowest precedence; used only when no YAML exists)
	fileNameYML  = "issue-detector.yml"  // alternate YAML extension (between .json and .yaml)
)

// Config mirrors the on-disk YAML shape.
type Config struct {
	Jobs         int           `yaml:"jobs"`          // worker MaxWorkers; 0 = NumCPU
	SubWorker    int           `yaml:"sub_worker"`    // sub-worker fan-out per file
	MaxFileSize  int64         `yaml:"max_file_size"` // bytes; files larger are skipped
	Timeout      time.Duration `yaml:"timeout"`       // whole-scan budget
	FailOn       string        `yaml:"fail_on"`       // none|low|medium|high|critical
	SeverityMin  string        `yaml:"severity_min"`  // minimum severity to report
	Categories   []string      `yaml:"categories"`    // enabled categories
	Ignore       []string      `yaml:"ignore"`        // extra ignore globs
	Skip         []string      `yaml:"skip"`          // alias for ignore (e.g. test files)
	Remote       string        `yaml:"remote"`        // git URL to clone
	Base         string        `yaml:"base"`          // delta scan base ref (PRD §3.4)
	Diff         string        `yaml:"diff"`          // delta scan patch file
	NoGit        bool          `yaml:"no_git"`        // skip git health analysis
	Rules        []string      `yaml:"rules"`         // extra rule files/dirs (PRD §8)
	RulesDir     string        `yaml:"rules_dir"`     // default rule dir (default .issue-detector/rules)
	ScoreWeights score.Weights `yaml:"score_weights"` // priority score coefficients (roast v9)
	AI           AIConfig      `yaml:"ai"`            // AI enrichment (Mode B, PRD §6.3)
	Cache        CacheConfig   `yaml:"cache"`         // session/change cache (PRD §10)
}

// CacheConfig controls where the session/change cache (main change path) lives.
//
// Everything defaults to the per-user dir so nothing is written into the
// scanned project. Mode selects the location:
//   - auto   (default): per-user global dir (~/.issues_detector/cache).
//   - global : per-user global dir (~/.issues_detector/cache).
//   - local  : next to the executable (opt-in; pollutes the install dir).
//
// Path is a custom main change path that overrides Mode when set.
// Enabled defaults to true (nil = enabled). MaxItems caps how many change items
// are retained per session (LRU trim; 0 = default 50) so long-lived agent
// sessions don't grow unbounded (PRD §10 risk table).
type CacheConfig struct {
	Enabled  *bool  `yaml:"enabled"`
	Mode     string `yaml:"mode"`
	Path     string `yaml:"path"`
	MaxItems int    `yaml:"max_items"`
}

// AIConfig mirrors the `ai:` YAML block (Mode B enrichment).
type AIConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Provider     string `yaml:"provider"`      // openai | gemini
	Model        string `yaml:"model"`         // default per provider
	BaseURL      string `yaml:"base_url"`      // override endpoint (Ollama/vLLM/Azure/…)
	APIKey       string `yaml:"api_key"`       // literal key (opsional; hati-hati jangan di-commit)
	APIKeyEnv    string `yaml:"api_key_env"`   // nama env var key; default per provider
	MaxFindings  int    `yaml:"max_findings"`  // cap temuan di-enrich / AI-only
	BudgetTokens int    `yaml:"budget_tokens"` // budget token
	CacheDir     string `yaml:"cache_dir"`
	Only         bool   `yaml:"only"`      // AI-detector mode (skip rule engine, PRD §3.2)
	MaxFiles     int    `yaml:"max_files"` // cap file dikirim ke AI pada mode --ai-only
}

// Default returns the baked-in defaults (PRD §10 performa/default flags).
func Default() Config {
	return Config{
		Jobs:        0,
		SubWorker:   5,
		MaxFileSize: 1024 * 1024, // 1 MB (PRD §10)
		Timeout:     0,           // no timeout unless set
		FailOn:      "none",
		SeverityMin: "",
		Categories:  nil, // all
		Ignore:      nil,
		Remote:      "",
	}
}

// MergeLayer overlays one config onto another; only non-zero fields with meaningful
// defaults replace. Used for flag-over-file precedence.
func MergeLayer(base, overlay Config) Config {
	out := base
	if overlay.Jobs != 0 {
		out.Jobs = overlay.Jobs
	}
	if overlay.SubWorker != 0 {
		out.SubWorker = overlay.SubWorker
	}
	if overlay.MaxFileSize != 0 {
		out.MaxFileSize = overlay.MaxFileSize
	}
	if overlay.Timeout != 0 {
		out.Timeout = overlay.Timeout
	}
	if overlay.FailOn != "" {
		out.FailOn = overlay.FailOn
	}
	if overlay.SeverityMin != "" {
		out.SeverityMin = overlay.SeverityMin
	}
	if overlay.Categories != nil {
		out.Categories = overlay.Categories
	}
	if overlay.Ignore != nil {
		out.Ignore = overlay.Ignore
	}
	if overlay.Remote != "" {
		out.Remote = overlay.Remote
	}
	out.AI = mergeAI(out.AI, overlay.AI)
	return out
}

func mergeAI(base, over AIConfig) AIConfig {
	if over.Enabled {
		base.Enabled = true
	}
	if over.Provider != "" {
		base.Provider = over.Provider
	}
	if over.Model != "" {
		base.Model = over.Model
	}
	if over.BaseURL != "" {
		base.BaseURL = over.BaseURL
	}
	if over.APIKey != "" {
		base.APIKey = over.APIKey
	}
	if over.APIKeyEnv != "" {
		base.APIKeyEnv = over.APIKeyEnv
	}
	if over.MaxFindings != 0 {
		base.MaxFindings = over.MaxFindings
	}
	if over.BudgetTokens != 0 {
		base.BudgetTokens = over.BudgetTokens
	}
	if over.CacheDir != "" {
		base.CacheDir = over.CacheDir
	}
	if over.Only {
		base.Only = true
	}
	if over.MaxFiles != 0 {
		base.MaxFiles = over.MaxFiles
	}
	return base
}

// Load reads the config file at path (empty path = no file) and returns merged
// defaults. Missing file is not an error unless failIfMissing is true.
func Load(path string, failIfMissing bool) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !failIfMissing {
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	// `skip` is an alias for `ignore`; normalize so downstream (fetcher, flags)
	// only ever reads Ignore.
	if len(cfg.Skip) > 0 {
		cfg.Ignore = append(cfg.Ignore, cfg.Skip...)
		cfg.Skip = nil
	}
	return cfg, nil
}

// Discover returns the highest-precedence project config path under root, or ""
// when none exists. Precedence (highest first): issue-detector.yaml >
// issue-detector.yml > issue-detector.json. YAML always wins over JSON: only the
// single highest-precedence file is used, the rest are ignored. An explicit
// --config path always wins over discovery. Directories are skipped.
func Discover(root string) string {
	names := []string{FileName, fileNameYML, FileNameJSON}
	for _, name := range names {
		p := filepath.Join(root, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// LoadProject resolves the effective project config for root. When explicit is
// non-empty it is loaded alone and must exist. Otherwise the single
// highest-precedence project file is used (issue-detector.yaml > .yml > .json),
// so YAML always wins over JSON; the other files are ignored. A project only
// needs one config file (PRD §7.2). Missing files are not an error.
//
// Returns the config and the source path (empty when no project file was found),
// so callers can log exactly which file was used.
func LoadProject(root, explicit string) (Config, string, error) {
	cfg := Default()

	// Base layer: the per-user global config (~/.issues_detector/issue-detector.yaml)
	// supplies defaults for every section (ai, cache, …); the project config and
	// CLI flags override it. A missing global file is a no-op.
	if gp, err := GlobalConfigPath(); err == nil {
		if _, serr := os.Stat(gp); serr == nil {
			if derr := decodeInto(gp, &cfg); derr != nil {
				return Config{}, "", derr
			}
		}
	}

	// Project layer: explicit --config wins; otherwise first-found discovery.
	p := explicit
	if p == "" {
		p = Discover(root)
	}
	if p == "" {
		return cfg, "", nil
	}
	globalAI := cfg.AI
	if err := decodeInto(p, &cfg); err != nil {
		return Config{}, "", err
	}
	// A project `ai:` block only overrides fields it actually sets; empty
	// strings / false inherit the per-user global layer (PRD §7.1). Without
	// this, a full-dump project file with blank ai fields would clobber the
	// global provider/model/base_url/api_key and silently break AI.
	cfg.AI = mergeAI(globalAI, cfg.AI)
	return cfg, p, nil
}

// decodeInto reads a YAML/JSON config file and unmarshals it onto cfg (in place),
// so layered callers keep values not present in the file. `skip` is normalized
// onto `ignore`.
func decodeInto(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(cfg.Skip) > 0 {
		cfg.Ignore = append(cfg.Ignore, cfg.Skip...)
		cfg.Skip = nil
	}
	return nil
}

// GlobalDir returns the per-user directory for config/cache (~/.issues_detector).
// ISSUE_DETECTOR_HOME overrides the home base (tests/CI).
func GlobalDir() (string, error) {
	home := os.Getenv("ISSUE_DETECTOR_HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		home = h
	}
	return filepath.Join(home, ".issues_detector"), nil
}

// GlobalConfigPath returns the per-user config path so cache settings stay out
// of the scanned project (roast: cache config must not live in the target repo).
func GlobalConfigPath() (string, error) {
	return GlobalPath("issue-detector.yaml")
}

// GlobalPath joins elem under the per-user dir (~/.issues_detector). All
// tool-managed state (config, session cache, AI cache, history) lives here so
// nothing is written into the scanned project. ISSUE_DETECTOR_HOME overrides
// the home base (tests/CI).
func GlobalPath(elem ...string) (string, error) {
	d, err := GlobalDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{d}, elem...)...), nil
}

// MergeCache overlays cache settings: non-nil/non-empty overlay fields win.
func MergeCache(base, overlay CacheConfig) CacheConfig {
	if overlay.Enabled != nil {
		base.Enabled = overlay.Enabled
	}
	if overlay.Mode != "" {
		base.Mode = overlay.Mode
	}
	if overlay.Path != "" {
		base.Path = overlay.Path
	}
	if overlay.MaxItems > 0 {
		base.MaxItems = overlay.MaxItems
	}
	return base
}

// ApplyGlobalCache overlays the cache block from the per-user config
// (~/.issues_detector/issue-detector.yaml) onto cfg. Settings already present
// in cfg (project config) take precedence. Missing global file is a no-op.
func ApplyGlobalCache(cfg Config) Config {
	path, err := GlobalConfigPath()
	if err != nil {
		return cfg
	}
	g, err := Load(path, false)
	if err != nil {
		return cfg
	}
	cfg.Cache = MergeCache(g.Cache, cfg.Cache)
	return cfg
}
