package pack

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzExtractTarGz feeds untrusted bytes to the pack extractor: it must never
// panic and must never write outside the target directory (path traversal).
func FuzzExtractTarGz(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}) // gzip magic, truncated
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		_ = extractTarGz(data, dir) // errors are fine; panic/escape are not

		_ = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			rel, rerr := filepath.Rel(dir, p)
			if rerr == nil && (rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				t.Fatalf("extracted path escaped the target dir: %s", rel)
			}
			return nil
		})
	})
}
