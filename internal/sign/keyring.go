// Package sign verifies detached ed25519 signatures against a keyring of
// trusted public keys (PRD §6.5 rule-pack signature & keyring).
package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
)

// ParsePublicKey decodes a base64 ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

// LoadKeyring reads base64 public keys, one per line. Blank lines and
// whitespace-separated trailing comments/labels are ignored.
func LoadKeyring(path string) ([]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []ed25519.PublicKey
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, " \t#"); i >= 0 {
			line = line[:i]
		}
		k, err := ParsePublicKey(line)
		if err != nil {
			continue
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Verify reports whether sig is a valid ed25519 signature of data under any key.
func Verify(keys []ed25519.PublicKey, data, sig []byte) bool {
	for _, k := range keys {
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
