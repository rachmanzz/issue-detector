package clone

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/fetcher"
)

func write(t *testing.T, dir, name, content string) fetcher.Entry {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return fetcher.Entry{Path: p, RelPath: name, Size: int64(len(content))}
}

func block(fn string) string {
	lines := []string{"func " + fn + "(x, y int) int {"}
	for i := 0; i < 40; i++ {
		lines = append(lines, "    if x > y { x = x + y - 1 } else { y = y - x + 2 }")
	}
	lines = append(lines, "    return x + y", "}")
	return strings.Join(lines, "\n")
}

func TestDetectCloneAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	e1 := write(t, dir, "a.go", block("alpha"))
	e2 := write(t, dir, "b.go", block("beta"))

	fs := Detect([]fetcher.Entry{e1, e2}, 20)
	if len(fs) == 0 {
		t.Fatal("expected a clone finding")
	}
	if fs[0].RuleID != "DUP-001" {
		t.Errorf("unexpected rule %s", fs[0].RuleID)
	}
}

func TestNoCloneOnDistinct(t *testing.T) {
	dir := t.TempDir()
	var a, b strings.Builder
	a.WriteString("package a\nfunc A() { println(1) }\n")
	b.WriteString("package b\nfunc B() { println(2) }\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&a, "a%d := %d + 1\n", i, i*3)
		fmt.Fprintf(&b, "b%d := %d * 2\n", i, i*7+1)
	}
	e1 := write(t, dir, "a.go", a.String())
	e2 := write(t, dir, "b.go", b.String())
	if fs := Detect([]fetcher.Entry{e1, e2}, 30); len(fs) != 0 {
		t.Errorf("distinct code should not be flagged: %+v", fs)
	}
}
