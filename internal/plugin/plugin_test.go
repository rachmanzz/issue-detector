package plugin

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// buildPlugin compiles a tiny WASI command module that reports PLUGINMARK hits.
func buildPlugin(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("wasip1 build not supported on windows")
	}
	src := `package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	var fs []map[string]any
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, _ := os.ReadFile(p)
		for i, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, "PLUGINMARK") {
				fs = append(fs, map[string]any{
					"rule_id": "PLUGIN-MARK", "category": "security", "severity": "medium",
					"title": "marker found", "message": "PLUGINMARK seen", "file": p, "line": i + 1,
				})
			}
		}
		return nil
	})
	_ = json.NewEncoder(os.Stdout).Encode(fs)
}
`
	mod := filepath.Join(dir, "mod")
	if err := os.MkdirAll(mod, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mod, "go.mod"), []byte("module markermod\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mod, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "marker.wasm")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = mod
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if err := cmd.Run(); err != nil {
		t.Skipf("plugin build unavailable: %v", err)
	}
	return out
}

func TestRunPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	dir := t.TempDir()
	wasm := buildPlugin(t, dir)

	root := filepath.Join(dir, "scan")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src.go"), []byte("package x\n// PLUGINMARK here\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fs := Run(context.Background(), root, []Plugin{{Name: "marker", Path: wasm}})
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %+v", fs)
	}
	if fs[0].RuleID != "PLUGIN-MARK" || fs[0].Source != "plugin" || fs[0].Line != 2 {
		t.Errorf("bad finding: %+v", fs[0])
	}
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.wasm"), []byte("\x00asm"), 0o644); err != nil {
		t.Fatal(err)
	}
	ps := Discover([]string{dir})
	if len(ps) != 1 || ps[0].Name != "a" {
		t.Fatalf("got %+v", ps)
	}
}
