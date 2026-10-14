// Package config loads scan options from a YAML file with sensible defaults
// (PRD §7 `--config`). Flags passed by the CLI override file values.
package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rachmanzz/issue-detector/internal/score"
)

// Default filenames resolved at scan root.
const FileName = "issue-detector.yaml"

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
	MaxFindings  int    `yaml:"max_findings"`  // cap temuan di-enrich
	BudgetTokens int    `yaml:"budget_tokens"` // budget token (perkiraan)
	CacheDir     string `yaml:"cache_dir"`
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
	return cfg, nil
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
