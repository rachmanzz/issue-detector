// Package plugin runs optional WASM rule plugins (PRD §6.5). A plugin is a
// WASI command module built for GOOS=wasip1 (or any WASI target). The host runs
// it with args [name, "/"], mounting the scan root read-only (os.DirFS) at the
// guest's "/", and reads a JSON array of findings from stdout. The wazero
// runtime isolates the module: no host access beyond that read-only FS.
package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// Plugin is a loaded .wasm module.
type Plugin struct {
	Name string
	Path string
}

// Discover finds .wasm files among the given paths (files or directories).
func Discover(paths []string) []Plugin {
	var out []Plugin
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			matches, _ := filepath.Glob(filepath.Join(p, "*.wasm"))
			for _, m := range matches {
				out = append(out, Plugin{Name: strings.TrimSuffix(filepath.Base(m), ".wasm"), Path: m})
			}
			continue
		}
		out = append(out, Plugin{Name: strings.TrimSuffix(filepath.Base(p), ".wasm"), Path: p})
	}
	return out
}

// Run executes each plugin against root and returns normalized findings. A
// failing plugin is skipped (best-effort), never breaking the scan.
func Run(ctx context.Context, root string, plugins []Plugin) []model.Finding {
	var out []model.Finding
	for _, p := range plugins {
		findings, err := runOne(ctx, root, p)
		if err != nil {
			continue
		}
		out = append(out, findings...)
	}
	return out
}

func runOne(ctx context.Context, root string, p Plugin) ([]model.Finding, error) {
	wasmBytes, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, err
	}

	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		return nil, err
	}

	var stdout, stderr strings.Builder
	cfg := wazero.NewModuleConfig().
		WithArgs(p.Name, "/").
		WithStdout(&stdout).
		WithStderr(&stderr).
		WithName(p.Name)

	// Mount the scan root read-only at the guest's "/" (os.DirFS is read-only).
	if root != "" {
		cfg = cfg.WithFS(os.DirFS(root))
	}

	if _, err := r.InstantiateWithConfig(ctx, wasmBytes, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", p.Name, err)
	}

	return parseFindings(p.Name, stdout.String())
}

func parseFindings(name, stdout string) ([]model.Finding, error) {
	out := strings.TrimSpace(stdout)
	if out == "" {
		return nil, nil
	}
	if i := strings.Index(out, "["); i > 0 {
		out = out[i:]
	}
	var raw []model.Finding
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("%s: invalid findings json: %w", name, err)
	}
	for i := range raw {
		if raw[i].Source == "" {
			raw[i].Source = model.SourcePlugin
		}
		if raw[i].Category == "" {
			raw[i].Category = model.CategorySecurity
		}
		if raw[i].Severity == "" {
			raw[i].Severity = model.SeverityMedium
		}
		if raw[i].Confidence == 0 {
			raw[i].Confidence = 0.6
		}
		if raw[i].RuleID == "" {
			raw[i].RuleID = "PLUGIN-" + strings.ToUpper(name)
		}
	}
	return raw, nil
}
