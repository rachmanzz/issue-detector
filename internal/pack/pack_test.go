package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

const ruleYAML = `id: PACK-001
category: security
severity: high
title: pack rule
match: {kind: regex, pattern: 'DANGER'}
`

func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(ruleYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := Load(dir, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].ID != "PACK-001" {
		t.Fatalf("got %+v", rs)
	}
}

func TestLoadSignedTarGz(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := makeTarGz(t, map[string]string{"rules/r.yaml": ruleYAML})
	path := filepath.Join(t.TempDir(), "pack.tar.gz")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", ed25519.Sign(priv, data), 0o644); err != nil {
		t.Fatal(err)
	}

	rs, err := Load(path, []ed25519.PublicKey{pub}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].ID != "PACK-001" {
		t.Fatalf("got %+v", rs)
	}
}

func TestLoadRejectsBadSignature(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	data := makeTarGz(t, map[string]string{"r.yaml": ruleYAML})
	path := filepath.Join(t.TempDir(), "pack.tar.gz")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", ed25519.Sign(priv, data), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, []ed25519.PublicKey{otherPub}, true); err == nil {
		t.Error("expected signature verification failure")
	}
}

func TestLoadRequiresSignature(t *testing.T) {
	data := makeTarGz(t, map[string]string{"r.yaml": ruleYAML})
	path := filepath.Join(t.TempDir(), "pack.tar.gz")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, nil, true); err == nil {
		t.Error("expected error when signature required but absent")
	}
}

// TestLoadSigWithoutKeyringRejected guards that a pack carrying a .sig but with
// an empty keyring is refused (never silently accepted unverified).
func TestLoadSigWithoutKeyringRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := makeTarGz(t, map[string]string{"r.yaml": ruleYAML})
	path := filepath.Join(t.TempDir(), "pack.tar.gz")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", ed25519.Sign(priv, data), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, nil, false); err == nil {
		t.Error("sig present with empty keyring must be rejected")
	}
}
