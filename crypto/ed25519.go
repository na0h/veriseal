package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadEd25519PrivateKey loads an Ed25519 private key from a PEM file.
// Supported format: PKCS#8 PEM ("BEGIN PRIVATE KEY").
func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("invalid private key: not PEM")
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: parse PKCS#8 failed: %w", err)
	}

	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key: not Ed25519")
	}
	return priv, nil
}

// LoadEd25519PublicKey loads an Ed25519 public key from a PEM file.
// Supported format: SubjectPublicKeyInfo PEM ("BEGIN PUBLIC KEY").
func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("invalid public key: not PEM")
	}

	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: parse PKIX failed: %w", err)
	}

	pub, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key: not Ed25519")
	}
	return pub, nil
}
