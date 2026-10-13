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
