// Package config loads scan options from a YAML file with sensible defaults
// (PRD §7 `--config`). Flags passed by the CLI override file values.
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Default filenames resolved at scan root.
const FileName = "issue-detector.yaml"

// Config mirrors the on-disk YAML shape.
type Config struct {
	Jobs        int           `yaml:"jobs"`          // worker MaxWorkers; 0 = NumCPU
	SubWorker   int           `yaml:"sub_worker"`    // sub-worker fan-out per file
	MaxFileSize int64         `yaml:"max_file_size"` // bytes; files larger are skipped
	Timeout     time.Duration `yaml:"timeout"`       // whole-scan budget
	FailOn      string        `yaml:"fail_on"`       // none|low|medium|high|critical
	SeverityMin string        `yaml:"severity_min"`  // minimum severity to report
	Categories  []string      `yaml:"categories"`    // enabled categories
	Ignore      []string      `yaml:"ignore"`        // extra ignore globs
	Remote      string        `yaml:"remote"`        // git URL to clone
	Base        string        `yaml:"base"`          // delta scan base ref (PRD §3.4)
	Diff        string        `yaml:"diff"`          // delta scan patch file
	NoGit       bool          `yaml:"no_git"`        // skip git health analysis
	Rules       []string      `yaml:"rules"`         // extra rule files/dirs (PRD §8)
	RulesDir    string        `yaml:"rules_dir"`     // default rule dir (default .issue-detector/rules)
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
	return out
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
