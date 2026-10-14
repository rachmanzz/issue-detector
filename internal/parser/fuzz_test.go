package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadFile exercises file reading on arbitrary content; it must never panic.
func FuzzReadFile(f *testing.F) {
	f.Add([]byte("package main\n\nfunc main(){}\n"), "a.go")
	f.Add([]byte{0x00, 0x01, 0x02}, "a.bin")
	f.Add([]byte(""), "empty.txt")

	f.Fuzz(func(t *testing.T, data []byte, name string) {
		dir := t.TempDir()
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Skip()
		}
		_, _ = ReadFile(p, name, int64(len(data)), 1<<20)
	})
}
