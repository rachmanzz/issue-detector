package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMCPReadsConfigFromRoot guards the regression where `mcp` loaded its
// project config from the current working directory instead of `--root`
// (roast v21): the server scans `--root` but must also read config from there.
func TestMCPReadsConfigFromRoot(t *testing.T) {
	t.Setenv("ISSUE_DETECTOR_HOME", t.TempDir())
	t.Setenv("ISSUE_DETECTOR_CACHE_DIR", t.TempDir())

	dir := t.TempDir()
	// A secret that is only suppressed if the config at --root is honored.
	if err := os.WriteFile(filepath.Join(dir, "keys.pem"),
		[]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "issue-detector.yaml"),
		[]byte("ignore:\n  - \"keys.pem\"\nno_git: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan","arguments":{"no_deps":true,"no_git":true}}}` + "\n"

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetArgs([]string{
		"mcp",
		"--root", dir,
		"--history", filepath.Join(t.TempDir(), "h.db"),
		"--baseline", filepath.Join(t.TempDir(), "b.json"),
	})
	root.SetIn(strings.NewReader(req))
	root.SetOut(&out)
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "keys.pem") {
		t.Errorf("config dari --root tidak dipakai: keys.pem harus ter-ignore\n%s", out.String())
	}
}
