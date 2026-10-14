// Package sign verifies detached ed25519 signatures against a keyring of
// trusted public keys (PRD §6.5 rule-pack signature & keyring).
package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// ParsePublicKey decodes a base64 ed25519 public key. A key that does not decode
// to exactly ed25519.PublicKeySize bytes is an error (never a silent nil key).
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: panjang kunci %d byte, harus %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// LoadKeyring reads base64 public keys, one per line. Blank lines and
// whitespace-separated trailing comments/labels are ignored. A line that looks
// like a key but does not parse is a hard error (no silent skips), so a typo
// can never be mistaken for "protection is on".
func LoadKeyring(path string) ([]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := parseKeyring(string(data))
	if err != nil {
		return nil, fmt.Errorf("keyring %s: %w", path, err)
	}
	if len(f) == 0 {
		return nil, fmt.Errorf("keyring %s: tidak ada kunci publik valid", path)
	}
	return f, nil
}

// parseKeyring parses keyring text; it returns an error on the first non-blank,
// non-comment line that is not a valid ed25519 public key.
func parseKeyring(text string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if j := strings.IndexAny(line, " \t#"); j >= 0 {
			line = line[:j]
		}
		k, err := ParsePublicKey(line)
		if err != nil {
			return nil, fmt.Errorf("baris %d: %w", i+1, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Verify reports whether sig is a valid ed25519 signature of data under any key.
// Keys of an unexpected length are skipped (defense in depth: never panic).
func Verify(keys []ed25519.PublicKey, data, sig []byte) bool {
	for _, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(k, data, sig) {
			return true
		}
	}
	return false
}

// VerifyFile verifies the detached signature file against data.
func VerifyFile(keys []ed25519.PublicKey, data []byte, sigPath string) bool {
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return false
	}
	return Verify(keys, data, sig)
}
