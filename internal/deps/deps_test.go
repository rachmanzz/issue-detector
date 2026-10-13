package deps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/fetcher"
	"github.com/rachmanzz/issue-detector/internal/model"
)

func entries(t *testing.T, files map[string]string) []fetcher.Entry {
	t.Helper()
	dir := t.TempDir()
	var es []fetcher.Entry
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		es = append(es, fetcher.Entry{Path: p, RelPath: rel})
	}
	return es
}

func TestDiscoverGoMod(t *testing.T) {
	es := entries(t, map[string]string{
		"go.mod": `module example.com/x

go 1.22

require (
	github.com/foo/bar v1.2.3
	golang.org/x/text v0.14.0 // indirect
)
`,
	})
	res := Discover(es)
	if len(res.Deps) != 2 {
		t.Fatalf("want 2 deps, got %+v", res.Deps)
	}
	if res.Deps[0].Name != "github.com/foo/bar" || res.Deps[0].Version != "v1.2.3" || res.Deps[0].Ecosystem != "Go" {
		t.Errorf("bad dep: %+v", res.Deps[0])
	}
	// no go.sum → DEP-002
	if !hasRule(res.Findings, "DEP-002") {
		t.Errorf("expected DEP-002 (missing lockfile), got %+v", res.Findings)
	}
}

func TestDiscoverPackageJSON(t *testing.T) {
	es := entries(t, map[string]string{
		"package.json": `{"dependencies":{"lodash":"4.17.21","express":"^4.18.0"}}`,
	})
	res := Discover(es)
	names := map[string]string{}
	for _, d := range res.Deps {
		names[d.Name] = d.Version
	}
	if names["lodash"] != "4.17.21" {
		t.Errorf("lodash version = %q", names["lodash"])
	}
	if names["express"] != "4.18.0" {
		t.Errorf("express cleaned version = %q", names["express"])
	}
	if !hasRule(res.Findings, "DEP-003") { // express ^ unpinned
		t.Errorf("expected DEP-003 for express, got %+v", res.Findings)
	}
	if !hasRule(res.Findings, "DEP-002") { // no lockfile
		t.Errorf("expected DEP-002, got %+v", res.Findings)
	}
}

func TestDiscoverRequirements(t *testing.T) {
	es := entries(t, map[string]string{
		"requirements.txt": "requests==2.31.0\nflask>=3.0\n# comment\n",
	})
	res := Discover(es)
	if len(res.Deps) != 2 {
		t.Fatalf("want 2 deps, got %+v", res.Deps)
	}
	if !hasRule(res.Findings, "DEP-003") {
		t.Errorf("flask>=3.0 should be flagged unpinned")
	}
}

func hasRule(fs []model.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
