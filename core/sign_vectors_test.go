package core

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVector_V0_001(t *testing.T) {
	// 固定seed（32bytes）: 0,1,2,...,31
	seed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// 入力Envelope（署名前）
	path := filepath.Join("..", "testdata", "vectors", "v0_sign_001_input.json")

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}

	// 署名
	signed, err := SignEd25519(env, priv)
	if err != nil {
		t.Fatal(err)
	}

	// 期待sig（JCS + 上の固定seedで決まる）
	wantSig := "K4s3ikAflettROOXN/nA/UcFBiIAXtjBbFvrF2bgJ31qpmzQwMYlOvc+24AUQFnIkZHwEJJtRozTgq726NivAA=="
	if signed.Sig != wantSig {
		t.Fatalf("sig mismatch\n got: %s\nwant: %s", signed.Sig, wantSig)
	}

	// 検証も通ること
	if err := VerifyEd25519(signed, pub); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}
