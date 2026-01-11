package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func baseEnvelopeJCS() Envelope {
	return Envelope{
		V:               Version1,
		Alg:             V1AlgEd25519,
		Kid:             "demo-1",
		PayloadEncoding: V1PayloadEncodingJCS,
		PayloadHashAlg:  V1PayloadHashAlgSHA256,
	}
}

func baseEnvelopeRaw() Envelope {
	return Envelope{
		V:               Version1,
		Alg:             V1AlgEd25519,
		Kid:             "demo-1",
		PayloadEncoding: V1PayloadEncodingRaw,
		PayloadHashAlg:  V1PayloadHashAlgSHA256,
	}
}

func TestV1_SignVerify_OK(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"a":1,"b":2}`)
	env := baseEnvelopeJCS()

	signed, err := SignEd25519(env, payload, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := VerifyEd25519(signed, pub); err != nil {
		t.Fatalf("verify sig: %v", err)
	}
	if err := VerifyPayloadHash(signed, payload); err != nil {
		t.Fatalf("verify payload hash: %v", err)
	}
}

func TestV1_PayloadChanged_Fails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	orig := []byte(`{"a":1,"b":2}`)
	env := baseEnvelopeJCS()

	signed, err := SignEd25519(env, orig, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyEd25519(signed, pub); err != nil {
		t.Fatalf("verify sig: %v", err)
	}

	changed := []byte(`{"a":1,"b":3}`)
	if err := VerifyPayloadHash(signed, changed); err == nil {
		t.Fatalf("want payload hash mismatch, got nil")
	}
}

func TestV1_JSONOrderDifferent_OK(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	a := []byte(`{"a":1,"b":2}`)
	b := []byte(`{"b":2,"a":1}`) // semantic same

	env := baseEnvelopeJCS()
	signed, err := SignEd25519(env, a, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// payload hash should still validate for reordered JSON
	if err := VerifyPayloadHash(signed, b); err != nil {
		t.Fatalf("verify payload hash: %v", err)
	}
}

func TestV1_SignVerify_RawPayload_OK(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// raw payload: arbitrary bytes (not necessarily UTF-8 / JSON)
	payload := []byte{0x00, 0x01, 0x02, 0xff}
	env := baseEnvelopeRaw()

	signed, err := SignEd25519(env, payload, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := VerifyEd25519(signed, pub); err != nil {
		t.Fatalf("verify sig: %v", err)
	}
	if err := VerifyPayloadHash(signed, payload); err != nil {
		t.Fatalf("verify payload hash: %v", err)
	}
}

func TestV1_Verify_RawPayload_OneByteModified_Fail(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{0x10, 0x20, 0x30, 0x40}
	env := baseEnvelopeRaw()

	signed, err := SignEd25519(env, payload, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// signature should still verify against the envelope
	if err := VerifyEd25519(signed, pub); err != nil {
		t.Fatalf("verify sig: %v", err)
	}

	mut := append([]byte(nil), payload...)
	mut[2] ^= 0x01
	if err := VerifyPayloadHash(signed, mut); err == nil {
		t.Fatalf("want payload hash mismatch, got nil")
	}
}

func TestV1_Verify_RawVsJCS_Mismatch_Fail(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Same semantic JSON, but raw vs JCS normalization must not be mixed.
	rawPayload := []byte(`{"a":1,"b":2}`)
	jcsPayload := []byte(`{"b":2,"a":1}`)

	env := baseEnvelopeRaw()
	signed, err := SignEd25519(env, rawPayload, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify payload hash with JCS payload must fail because encoding differs.
	if err := VerifyPayloadHash(signed, jcsPayload); err == nil {
		t.Fatalf("want payload hash mismatch, got nil")
	}
}

func TestV1_Validate_VersionInvalid_Fail(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	env := baseEnvelopeJCS()
	env.V = 2

	_, err = SignEd25519(env, []byte(`{"a":1}`), priv)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestV1_Validate_PayloadEncodingMissing_Fail(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	env := baseEnvelopeJCS()
	env.PayloadEncoding = ""

	_, err = SignEd25519(env, []byte(`{"a":1}`), priv)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !strings.Contains(err.Error(), "missing payload_encoding") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestV1_Validate_PayloadEncodingUnsupported_Fail(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	env := baseEnvelopeJCS()
	env.PayloadEncoding = "rawx"

	_, err = SignEd25519(env, []byte(`{"a":1}`), priv)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported payload_encoding") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestV1_Validate_PayloadHashAlgUnsupported_Fail(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	env := baseEnvelopeJCS()
	env.PayloadHashAlg = "sha1"

	_, err = SignEd25519(env, []byte(`{"a":1}`), priv)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported payload_hash_alg") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestV1_Validate_VerifyMissingPayloadHash_Fail(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	env := baseEnvelopeJCS()
	signed, err := SignEd25519(env, []byte(`{"a":1}`), priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	signed.PayloadHash = ""
	if err := VerifyEd25519(signed, pub); err == nil {
		t.Fatalf("want error, got nil")
	}
}

func TestV1_Validate_VerifyMissingSig_Fail(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	env := baseEnvelopeJCS()
	signed, err := SignEd25519(env, []byte(`{"a":1}`), priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	signed.Sig = nil
	if err := VerifyEd25519(signed, pub); err == nil {
		t.Fatalf("want error, got nil")
	}
}
