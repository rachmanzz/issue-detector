package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte("rule pack bytes")
	sig := ed25519.Sign(priv, data)

	if !Verify([]ed25519.PublicKey{pub}, data, sig) {
		t.Error("valid signature rejected")
	}
	if Verify([]ed25519.PublicKey{pub}, []byte("tampered"), sig) {
		t.Error("tampered data accepted")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if Verify([]ed25519.PublicKey{otherPub}, data, sig) {
		t.Error("wrong key accepted")
	}
}

func TestLoadKeyring(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "keys.txt")
	content := "# trusted keys\n\n" +
		base64.StdEncoding.EncodeToString(pub) + "  maintainer\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys[0].Equal(pub) {
		t.Fatalf("keyring mismatch: %d keys", len(keys))
	}
}
