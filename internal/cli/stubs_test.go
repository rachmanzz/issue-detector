package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/config"
)

// TestInitTemplateDoesNotClobberGlobalAI guards that `issue-detector init` no
// longer writes an active (empty) ai: block. Such a block would override the
// per-user config at the project layer and silently disable AI.
func TestInitTemplateDoesNotClobberGlobalAI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ISSUE_DETECTOR_HOME", home)
	gdir := filepath.Join(home, ".issues_detector")
	if err := os.MkdirAll(gdir, 0o755); err != nil {
		t.Fatal(err)
	}
	global := "ai:\n  enabled: true\n  provider: openai\n  model: global-model\n  base_url: https://example.test/v1\n"
	if err := os.WriteFile(filepath.Join(gdir, config.FileName), []byte(global), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	t.Chdir(dir)
	if err := writeDefaultConfig(); err != nil {
		t.Fatal(err)
	}

	cfg, src, err := config.LoadProject(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if src == "" {
		t.Fatal("generated project config not discovered")
	}
	if !cfg.AI.Enabled || cfg.AI.Provider != "openai" ||
		cfg.AI.Model != "global-model" || cfg.AI.BaseURL != "https://example.test/v1" {
		t.Fatalf("init template clobbered per-user AI: %+v", cfg.AI)
	}
}
