package cli

import (
	"os"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/config"
)

func TestWriteGlobalCacheMode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("ISSUE_DETECTOR_HOME", home)

	if err := writeGlobalCacheMode("global"); err != nil {
		t.Fatal(err)
	}
	gp, err := config.GlobalConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(gp, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cache.Mode != "global" {
		t.Fatalf("mode = %q, want global", cfg.Cache.Mode)
	}

	// Rewriting must preserve unrelated keys and existing cache fields.
	if err := os.WriteFile(gp, []byte("jobs: 4\ncache:\n  enabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeGlobalCacheMode("local"); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(gp, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Jobs != 4 {
		t.Errorf("unrelated key jobs lost: %d", cfg.Jobs)
	}
	if cfg.Cache.Mode != "local" {
		t.Errorf("mode = %q, want local", cfg.Cache.Mode)
	}
	if cfg.Cache.Enabled == nil || !*cfg.Cache.Enabled {
		t.Errorf("enabled should be preserved: %+v", cfg.Cache.Enabled)
	}
}
