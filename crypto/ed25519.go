package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	s := strings.TrimSpace(string(b))
	if s != "" && looksBase64(s) {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return toPrivateKey(raw)
	}

	return toPrivateKey(b)
}

func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	s := strings.TrimSpace(string(b))
	if s != "" && looksBase64(s) {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return toPublicKey(raw)
	}

	return toPublicKey(b)
}

func toPrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	raw = bytesTrimSpace(raw)
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key size (expected 64 bytes)")
	}
	return ed25519.PrivateKey(raw), nil
}

func toPublicKey(raw []byte) (ed25519.PublicKey, error) {
	raw = bytesTrimSpace(raw)
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size (expected 32 bytes)")
	}
	return ed25519.PublicKey(raw), nil
}

func looksBase64(s string) bool {
	if len(s)%4 != 0 {
		return false
	}
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '+' || r == '/' || r == '=' || r == '\n' || r == '\r' || r == '\t' || r == ' ' {
			continue
		}
		return false
	}
	return true
}

func bytesTrimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}
