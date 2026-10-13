// Package parser reads source files into model.File and detects language.
//
// M0 ships the line-based engine only. Language-aware AST parsing lands later
// via tree-sitter (PRD §5.1 "Parser"); unsupported languages already fall back
// to this line engine by design.
package parser

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/model"
)

// BinarySignatures are prefixes that mark a file as binary, so we never read
// megabytes of non-source content into memory.
var BinarySignatures = [][]byte{
	{0x00},
	{0xff, 0xd8, 0xff},       // jpeg
	{0x89, 0x50, 0x4e, 0x47}, // png
	{0x50, 0x4b, 0x03, 0x04}, // zip
}

// BinaryExts are file extensions treated as binary regardless of content.
var BinaryExts = map[string]bool{
	".png":    true,
	".jpg":    true,
	".jpeg":   true,
	".gif":    true,
	".ico":    true,
	".pdf":    true,
	".zip":    true,
	".gz":     true,
	".tar":    true,
	".bin":    true,
	".so":     true,
	".dll":    true,
	".exe":    true,
	".o":      true,
	".a":      true,
	".db":     true,
	".sqlite": true,
}

// DetectLanguage maps a file extension to a Language.
func DetectLanguage(path string) model.Language {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return model.LanguageGo
	case ".py", ".pyi":
		return model.LanguagePython
	case ".js", ".jsx", ".mjs", ".cjs":
		return model.LanguageJavaScript
	case ".ts", ".tsx":
		return model.LanguageTypeScript
	default:
		return model.LanguageUnknown
	}
}

// IsTextExtension reports whether the extension is a known binary format.
func IsBinaryExt(path string) bool {
	return BinaryExts[strings.ToLower(filepath.Ext(path))]
}

// ReadFile loads path into a model.File, honoring a size cap + ignore list.
// Skipped files are returned as *model.File with Skipped=true (not an error),
// so callers can attribute them to the scan summary instead of failing it.
func ReadFile(path, relPath string, size int64, maxSize int64) (*model.File, error) {
	f := &model.File{
		Path:     path,
		RelPath:  relPath,
		Size:     size,
		Language: DetectLanguage(path),
	}

	if IsBinaryExt(path) {
		f.Binary = true
		return f, nil
	}
	if size > maxSize {
		f.Skipped = true
		f.SkipReason = "exceeds max file size"
		return f, nil
	}
	if size == 0 {
		f.Skipped = true
		f.SkipReason = "empty file"
		return f, nil
	}

	fh, err := os.Open(path)
	if err != nil {
		return f, err
	}
	defer fh.Close()

	head := make([]byte, 512)
	n, _ := fh.Read(head)
	head = head[:n]
	for _, sig := range BinarySignatures {
		if bytes.HasPrefix(head, sig) {
			f.Binary = true
			return f, nil
		}
	}

	if _, err := fh.Seek(0, 0); err != nil {
		return f, err
	}

	f.Lines = make([]string, 0, 256)
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		f.Lines = append(f.Lines, strings.TrimRight(sc.Text(), "\r"))
	}
	if err := sc.Err(); err != nil {
		return f, err
	}
	return f, nil
}
