package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	cfg := Default()
	if cfg.MaxFileSize != 1024*1024 {
		t.Errorf("MaxFileSize default = %d", cfg.MaxFileSize)
	}
	if cfg.FailOn != "none" {
		t.Errorf("FailOn default = %q", cfg.FailOn)
	}
	if cfg.SubWorker != 5 {
		t.Errorf("SubWorker default = %d", cfg.SubWorker)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "issue-detector.yaml")
	content := "jobs: 4\nfail_on: high\nignore:\n  - '*.min.js'\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Jobs != 4 || cfg.FailOn != "high" || len(cfg.Ignore) != 1 {
		t.Errorf("loaded config mismatch: %+v", cfg)
	}
	// Defaults for unspecified fields preserved.
	if cfg.MaxFileSize != 1024*1024 {
		t.Errorf("MaxFileSize lost default after load: %d", cfg.MaxFileSize)
	}
}

func TestLoadAIBlock(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "issue-detector.yaml")
	content := `ai:
  enabled: true
  provider: gemini
  model: gemini-1.5-flash
  api_key_env: MY_KEY
  max_findings: 5
  budget_tokens: 4200
  cache_dir: .aica
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p, true)
	if err != nil {
		t.Fatal(err)
	}
	ai := cfg.AI
	if !ai.Enabled || ai.Provider != "gemini" || ai.Model != "gemini-1.5-flash" ||
		ai.APIKeyEnv != "MY_KEY" || ai.MaxFindings != 5 || ai.BudgetTokens != 4200 || ai.CacheDir != ".aica" {
		t.Errorf("AI block mismatch: %+v", ai)
	}
	// Default config should have AI disabled.
	if Default().AI.Enabled {
		t.Error("AI harus default off")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load("/nonexistent.yaml", false); err != nil {
		t.Errorf("missing file should be fine when not required: %v", err)
	}
	if _, err := Load("/nonexistent.yaml", true); err == nil {
		t.Error("missing file should error when required")
	}
}

func TestMergeLayer(t *testing.T) {
	base := Default()
	base.FailOn = "low"

	over := Default()
	over.Jobs = 8
	over.FailOn = "" // flag tidak di-set -> tidak menimpa base
	over.Timeout = 30 * time.Second

	out := MergeLayer(base, over)
	if out.Jobs != 8 {
		t.Errorf("jobs not overridden: %d", out.Jobs)
	}
	if out.FailOn != "low" {
		t.Errorf("fail_on should stay from base: %q", out.FailOn)
	}
	if out.Timeout != 30*time.Second {
		t.Errorf("timeout not overridden")
	}

	over2 := Default()
	over2.FailOn = "high"
	out2 := MergeLayer(base, over2)
	if out2.FailOn != "high" {
		t.Errorf("fail_on should be overridden when set: %q", out2.FailOn)
	}
}

func TestMergeCache(t *testing.T) {
	off := false
	base := CacheConfig{Mode: "global"}
	over := CacheConfig{Enabled: &off, Path: "/custom"}
	out := MergeCache(base, over)
	if out.Mode != "global" {
		t.Errorf("mode should stay from base: %q", out.Mode)
	}
	if out.Enabled == nil || *out.Enabled {
		t.Errorf("enabled should be overridden to false: %+v", out.Enabled)
	}
	if out.Path != "/custom" {
		t.Errorf("path should be overridden: %q", out.Path)
	}

	// Empty overlay leaves base untouched.
	if got := MergeCache(base, CacheConfig{}); got != base {
		t.Errorf("empty overlay changed base: %+v", got)
	}
}

func TestLoadCacheBlock(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "issue-detector.yaml")
	if err := os.WriteFile(p, []byte("cache:\n  enabled: true\n  mode: local\n  path: .cache-x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cache.Enabled == nil || !*cfg.Cache.Enabled || cfg.Cache.Mode != "local" || cfg.Cache.Path != ".cache-x" {
		t.Errorf("cache block mismatch: %+v", cfg.Cache)
	}
}

func TestApplyGlobalCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ISSUE_DETECTOR_HOME", home)
	dir := filepath.Join(home, ".issues_detector")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gp := filepath.Join(dir, "issue-detector.yaml")
	if err := os.WriteFile(gp, []byte("cache:\n  mode: global\n  path: /global-cache\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := ApplyGlobalCache(Default())
	if cfg.Cache.Mode != "global" || cfg.Cache.Path != "/global-cache" {
		t.Errorf("global cache not applied: %+v", cfg.Cache)
	}

	// Project-level cache settings take precedence over global.
	project := Default()
	project.Cache.Mode = "local"
	cfg = ApplyGlobalCache(project)
	if cfg.Cache.Mode != "local" {
		t.Errorf("project cache should win: %q", cfg.Cache.Mode)
	}
	if cfg.Cache.Path != "/global-cache" {
		t.Errorf("unspecified project field should inherit global: %q", cfg.Cache.Path)
	}
}
