package core

import (
	"crypto/ed25519"
	"testing"
)

func TestV1Vector_SignAndVerify(t *testing.T) {
	// 固定seed（32bytes）: 0..31
	seed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	payload := []byte("hello world") // 生bytes

	env := EnvelopeV1{
		V:              1,
		Alg:            "Ed25519",
		Kid:            "demo-1",
		PayloadHashAlg: "SHA-256",
		PayloadType:    "application/octet-stream",
	}

	signed, err := SignEd25519V1(env, payload, priv)
	if err != nil {
		t.Fatal(err)
	}

	// 署名検証（payload無しでもOK）
	if err := VerifyEd25519V1(signed, pub, nil); err != nil {
		t.Fatalf("verify (sig only) failed: %v", err)
	}

	// payload hash まで含めて検証
	if err := VerifyEd25519V1(signed, pub, payload); err != nil {
		t.Fatalf("verify (with payload) failed: %v", err)
	}

	// “固定値”として pin したければ、以下を一度だけ表示して README/ベクタに写す
	// t.Logf("payload_hash=%s sig=%s", signed.PayloadHash, signed.Sig)
}
