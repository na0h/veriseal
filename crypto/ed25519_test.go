package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeTempPEM(t *testing.T, typ string, der []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "key.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if b == nil {
		t.Fatalf("failed to encode PEM")
	}
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return p
}

func TestLoadEd25519PrivateKey_PKCS8_OK(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTempPEM(t, "PRIVATE KEY", der)

	got, err := LoadEd25519PrivateKey(path)
	if err != nil {
		t.Fatalf("LoadEd25519PrivateKey: %v", err)
	}
	if len(got) != ed25519.PrivateKeySize {
		t.Fatalf("unexpected private key size: %d", len(got))
	}
}

func TestLoadEd25519PublicKey_PKIX_OK(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTempPEM(t, "PUBLIC KEY", der)

	got, err := LoadEd25519PublicKey(path)
	if err != nil {
		t.Fatalf("LoadEd25519PublicKey: %v", err)
	}
	if len(got) != ed25519.PublicKeySize {
		t.Fatalf("unexpected public key size: %d", len(got))
	}
}

func TestLoadEd25519PrivateKey_RejectsNonEd25519(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTempPEM(t, "PRIVATE KEY", der)

	_, err = LoadEd25519PrivateKey(path)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
}

func TestLoadEd25519PublicKey_RejectsNonEd25519(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTempPEM(t, "PUBLIC KEY", der)

	_, err = LoadEd25519PublicKey(path)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
}
