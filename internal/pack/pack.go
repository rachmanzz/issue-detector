// Package pack loads rule packs — a directory of rule YAML or a .tar.gz bundle
// — optionally requiring a detached ed25519 signature (PRD §6.5).
package pack

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/rachmanzz/issue-detector/internal/rules"
	"github.com/rachmanzz/issue-detector/internal/sign"
)

// Load reads one pack and returns its rules. Directories are trusted local
// packs. Files (.tar.gz) may carry a detached `<file>.sig`; when requireSig is
// true a valid signature under keyring is mandatory.
func Load(path string, keyring []ed25519.PublicKey, requireSig bool) ([]*rules.Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		if requireSig {
			return nil, fmt.Errorf("pack %q: signature required but directories cannot be signed", path)
		}
		return loadFromDir(path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sigPath := path + ".sig"
	_, sigErr := os.Stat(sigPath)
	switch {
	case sigErr == nil && len(keyring) == 0:
		// A signature is present but there is no trusted key to check it: refuse
		// rather than silently accepting an unverified pack.
		return nil, fmt.Errorf("pack %q: ada %s tetapi keyring kosong", path, filepath.Base(sigPath))
	case sigErr == nil:
		if !sign.VerifyFile(keyring, data, sigPath) {
			return nil, fmt.Errorf("pack %q: signature tidak valid", path)
		}
	case requireSig:
		return nil, fmt.Errorf("pack %q: tanda tangan tidak ada", path)
	default:
		slog.Warn("pack dimuat tanpa verifikasi tanda tangan", "pack", path)
	}

	dir, err := os.MkdirTemp("", "issue-detector-pack-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := extractTarGz(data, dir); err != nil {
		return nil, fmt.Errorf("pack %q: %w", path, err)
	}
	return loadFromDir(dir)
}

// loadFromDir collects every *.yaml/*.yml under dir (recursively) and loads them.
func loadFromDir(dir string) ([]*rules.Rule, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml":
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}
	return rules.LoadPaths(files)
}

// LoadMany loads multiple packs, concatenating their rules.
func LoadMany(paths []string, keyring []ed25519.PublicKey, requireSig bool) ([]*rules.Rule, error) {
	var out []*rules.Rule
	for _, p := range paths {
		rs, err := Load(p, keyring, requireSig)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}

func extractTarGz(data []byte, dir string) error {
	gz, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dir, filepath.Clean("/"+hdr.Name))
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal path in pack: %s", hdr.Name)
		}
		if hdr.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		f, err := os.Create(target)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, io.LimitReader(tr, 8<<20)); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
}
