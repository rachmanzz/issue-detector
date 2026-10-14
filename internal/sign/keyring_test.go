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

// TestParsePublicKeyRejectsWrongLength guards that a base64 value that is not a
// 32-byte key is an error, never a silent (nil, nil).
func TestParsePublicKeyRejectsWrongLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	k, err := ParsePublicKey(short)
	if err == nil || k != nil {
		t.Fatalf("wrong-length key must error, got k=%v err=%v", k, err)
	}
}

// TestLoadKeyringMalformedErrorsAndNoPanic guards that a malformed keyring line
// is a hard error (not silently skipped into a nil key that panics on Verify).
func TestLoadKeyringMalformedErrorsAndNoPanic(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "keys.txt")
	content := base64.StdEncoding.EncodeToString(pub) + "\n" +
		base64.StdEncoding.EncodeToString(make([]byte, 16)) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err == nil {
		t.Error("malformed keyring line must error")
	}
}

// TestLoadKeyringEmptyErrors guards that a keyring with no valid key is an error
// (a typo must not look like a loaded keyring).
func TestLoadKeyringEmptyErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.txt")
	if err := os.WriteFile(path, []byte("# only a comment\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(path); err == nil {
		t.Error("empty keyring must error")
	}
}

// TestVerifyIgnoresNilKey guards that Verify never panics on a nil/odd key.
func TestVerifyIgnoresNilKey(t *testing.T) {
	if Verify([]ed25519.PublicKey{nil}, []byte("m"), make([]byte, ed25519.SignatureSize)) {
		t.Error("nil key must not verify")
	}
}
