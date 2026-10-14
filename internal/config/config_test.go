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

func TestLoadJSONConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "issue-detector.json")
	content := `{
  "jobs": 7,
  "fail_on": "high",
  "severity_min": "low",
  "max_file_size": 2048,
  "ignore": ["**/*.min.js"],
  "skip": ["**/*_test.go", "testdata/**"],
  "ai": {"enabled": true, "provider": "gemini", "max_findings": 3},
  "cache": {"enabled": true, "mode": "local", "max_items": 9}
}`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p, true)
	if err != nil {
		t.Fatalf("json load: %v", err)
	}
	if cfg.Jobs != 7 || cfg.FailOn != "high" || cfg.SeverityMin != "low" || cfg.MaxFileSize != 2048 {
		t.Errorf("scalar fields mismatch: %+v", cfg)
	}
	// skip is an alias for ignore and must be folded in.
	if len(cfg.Ignore) != 3 {
		t.Errorf("ignore+skip should merge to 3: %v", cfg.Ignore)
	}
	if cfg.Skip != nil {
		t.Errorf("skip alias should be normalized away: %v", cfg.Skip)
	}
	if !cfg.AI.Enabled || cfg.AI.Provider != "gemini" || cfg.AI.MaxFindings != 3 {
		t.Errorf("ai block mismatch: %+v", cfg.AI)
	}
	if cfg.Cache.Enabled == nil || !*cfg.Cache.Enabled || cfg.Cache.Mode != "local" || cfg.Cache.MaxItems != 9 {
		t.Errorf("cache block mismatch: %+v", cfg.Cache)
	}
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	if got := Discover(dir); got != "" {
		t.Errorf("empty dir should discover nothing, got %q", got)
	}

	// JSON alone is discovered.
	jsonPath := filepath.Join(dir, FileNameJSON)
	if err := os.WriteFile(jsonPath, []byte("jobs: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Discover(dir); got != jsonPath {
		t.Errorf("json should be discovered, got %q", got)
	}

	// .yml beats json.
	ymlPath := filepath.Join(dir, fileNameYML)
	if err := os.WriteFile(ymlPath, []byte("jobs: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Discover(dir); got != ymlPath {
		t.Errorf(".yml should beat json, got %q", got)
	}

	// .yaml beats both.
	yamlPath := filepath.Join(dir, FileName)
	if err := os.WriteFile(yamlPath, []byte("jobs: 3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Discover(dir); got != yamlPath {
		t.Errorf(".yaml should beat json/.yml, got %q", got)
	}
}

// TestLoadProjectYAMLWinsOverJSON guards the precedence: the single
// highest-precedence file is used, so YAML wins over JSON entirely and JSON is
// ignored — never the other way around (PRD §7.2).
func TestLoadProjectYAMLWinsOverJSON(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileNameJSON), []byte(`{
  "jobs": 7,
  "fail_on": "low",
  "ignore": ["json-only"],
  "ai": {"enabled": true, "provider": "gemini"}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// YAML is the only file used, so JSON's values (including its list) are ignored.
	yamlPath := filepath.Join(dir, FileName)
	if err := os.WriteFile(yamlPath, []byte("jobs: 3\nfail_on: high\nignore:\n  - yaml-only\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, src, err := LoadProject(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if src != yamlPath {
		t.Errorf("source should be the yaml file: got %q want %q", src, yamlPath)
	}
	if cfg.Jobs != 3 || cfg.FailOn != "high" {
		t.Errorf("yaml scalars must win: jobs=%d fail_on=%q", cfg.Jobs, cfg.FailOn)
	}
	if len(cfg.Ignore) != 1 || cfg.Ignore[0] != "yaml-only" {
		t.Errorf("json ignore must be ignored entirely: %v", cfg.Ignore)
	}
	// JSON block must not leak through: YAML had no ai block.
	if cfg.AI.Enabled || cfg.AI.Provider != "" {
		t.Errorf("json ai block must not leak: %+v", cfg.AI)
	}
}

// TestLoadProjectIgnoresJSONWhenYAMLExists ensures a project only needs one
// file: with only JSON present it is used, but a YAML file takes over entirely.
func TestLoadProjectIgnoresJSONWhenYAMLExists(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, FileNameJSON)
	if err := os.WriteFile(jsonPath, []byte(`{"jobs": 7}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, src, err := LoadProject(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if src != jsonPath || cfg.Jobs != 7 {
		t.Errorf("json-only project should load json: src=%q jobs=%d", src, cfg.Jobs)
	}
}

func TestLoadProjectExplicit(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	dir := t.TempDir()
	explicit := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(explicit, []byte("jobs: 9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Auto-discovery would find this JSON, but explicit must win and be alone.
	if err := os.WriteFile(filepath.Join(dir, FileNameJSON), []byte("jobs: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, src, err := LoadProject(dir, explicit)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Jobs != 9 || src != explicit {
		t.Errorf("explicit config not honored: jobs=%d src=%q", cfg.Jobs, src)
	}
}

func TestLoadJSONInvalid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileNameJSON)
	if err := os.WriteFile(p, []byte(`{"jobs": `), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, true); err == nil {
		t.Error("malformed JSON should error")
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

// TestLoadProjectInheritsGlobalAI guards that the per-user config is the base
// layer for the whole config (not just cache): a global ai: block must reach the
// caller while project fields override it.
func TestLoadProjectInheritsGlobalAI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ISSUE_DETECTOR_HOME", home)
	gdir := filepath.Join(home, ".issues_detector")
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		t.Fatal(err)
	}
	global := "jobs: 4\nai:\n  enabled: true\n  provider: openai\n  model: global-model\n  base_url: https://example.test/v1\n  api_key: sk-global\n"
	if err := os.WriteFile(filepath.Join(gdir, FileName), []byte(global), 0o644); err != nil {
		t.Fatal(err)
	}

	// No project config: global values must come through unchanged.
	cfg, src, err := LoadProject(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if src != "" {
		t.Errorf("no project config expected, got src=%q", src)
	}
	if cfg.Jobs != 4 || !cfg.AI.Enabled || cfg.AI.Provider != "openai" ||
		cfg.AI.Model != "global-model" || cfg.AI.BaseURL != "https://example.test/v1" ||
		cfg.AI.APIKey != "sk-global" {
		t.Fatalf("global config not inherited: %+v", cfg)
	}

	// Project config overrides only the fields it sets; the rest inherit global.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("ai:\n  model: project-model\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, src, err = LoadProject(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if src == "" || cfg.AI.Model != "project-model" {
		t.Errorf("project model should win: src=%q model=%q", src, cfg.AI.Model)
	}
	if !cfg.AI.Enabled || cfg.AI.Provider != "openai" || cfg.AI.APIKey != "sk-global" || cfg.Jobs != 4 {
		t.Errorf("project must inherit unspecified global fields: %+v", cfg)
	}
}

// TestProjectBlankAIFieldsInheritGlobal guards against a full-dump project
// config (e.g. a stale generated issue-detector.json) whose ai block has blank
// strings and enabled:false silently clobbering the per-user global AI config
// (blank base_url sent the global key to the wrong provider -> 401).
func TestProjectBlankAIFieldsInheritGlobal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ISSUE_DETECTOR_HOME", home)
	gdir := filepath.Join(home, ".issues_detector")
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		t.Fatal(err)
	}
	global := "ai:\n  enabled: true\n  provider: openai\n  model: global-model\n  base_url: https://example.test/v1\n  api_key: sk-global\n"
	if err := os.WriteFile(filepath.Join(gdir, FileName), []byte(global), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	project := `{"ai":{"enabled":false,"provider":"openai","model":"","base_url":"","api_key_env":"","max_findings":25}}`
	if err := os.WriteFile(filepath.Join(dir, FileNameJSON), []byte(project), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := LoadProject(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AI.Enabled || cfg.AI.Model != "global-model" ||
		cfg.AI.BaseURL != "https://example.test/v1" || cfg.AI.APIKey != "sk-global" {
		t.Fatalf("blank project ai fields must inherit global: %+v", cfg.AI)
	}
}

// TestStatePath guards that configured state locations never resolve to the CWD
// (which would write cache into the scanned project): relative paths anchor
// under the per-user dir, absolute paths pass through, and a missing home dir
// falls back to the OS temp dir.
func TestStatePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ISSUE_DETECTOR_HOME", home)
	gdir := filepath.Join(home, ".issues_detector")

	if got := StatePath("/abs/x", "def"); got != "/abs/x" {
		t.Errorf("absolute must pass through, got %q", got)
	}
	if got := StatePath("", "ai-cache"); got != filepath.Join(gdir, "ai-cache") {
		t.Errorf("empty -> global default, got %q", got)
	}
	if got := StatePath(".rel", "ai-cache"); got != filepath.Join(gdir, ".rel") {
		t.Errorf("relative must anchor under global dir, got %q", got)
	}

	// Home unavailable -> temp dir, never CWD.
	t.Setenv("ISSUE_DETECTOR_HOME", "")
	t.Setenv("HOME", "")
	got := StatePath("rel", "def")
	if !filepath.IsAbs(got) || filepath.Dir(got) == "." {
		t.Errorf("fallback must be absolute (temp), got %q", got)
	}
	if got != filepath.Join(os.TempDir(), "issues_detector", "rel") {
		t.Errorf("fallback should be under temp, got %q", got)
	}
}
