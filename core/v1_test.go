package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"regexp"
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

	signed, err := SignEd25519(env, payload, priv, false)
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

	signed, err := SignEd25519(env, orig, priv, false)
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
	signed, err := SignEd25519(env, a, priv, false)
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

	signed, err := SignEd25519(env, payload, priv, false)
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

	signed, err := SignEd25519(env, payload, priv, false)
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
	signed, err := SignEd25519(env, rawPayload, priv, false)
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

	_, err = SignEd25519(env, []byte(`{"a":1}`), priv, false)
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

	_, err = SignEd25519(env, []byte(`{"a":1}`), priv, false)
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

	_, err = SignEd25519(env, []byte(`{"a":1}`), priv, false)
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

	_, err = SignEd25519(env, []byte(`{"a":1}`), priv, false)
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
	signed, err := SignEd25519(env, []byte(`{"a":1}`), priv, false)
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
	signed, err := SignEd25519(env, []byte(`{"a":1}`), priv, false)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	signed.Sig = nil
	if err := VerifyEd25519(signed, pub); err == nil {
		t.Fatalf("want error, got nil")
	}
}

func TestV1_SignVerify_WithIatInInput_OK(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"a":1,"b":2}`)
	env := baseEnvelopeJCS()
	v := int64(1700000000)
	env.Iat = &v

	signed, err := SignEd25519(env, payload, priv, false)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.Iat == nil || *signed.Iat != v {
		t.Fatalf("iat not preserved: got %v", signed.Iat)
	}

	if err := VerifyEd25519(signed, pub); err != nil {
		t.Fatalf("verify sig: %v", err)
	}
}

func TestV1_SignVerify_SetIat_OverwritesAndVerifies_OK(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"a":1,"b":2}`)
	env := baseEnvelopeJCS()
	old := int64(1700000000)
	env.Iat = &old

	signed, err := SignEd25519(env, payload, priv, true)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.Iat == nil {
		t.Fatalf("iat should be set")
	}
	if *signed.Iat == old {
		t.Fatalf("iat should be overwritten")
	}

	if err := VerifyEd25519(signed, pub); err != nil {
		t.Fatalf("verify sig: %v", err)
	}
}

func TestV1_SignVerify_SetIat_WhenMissing_OK(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"a":1,"b":2}`)
	env := baseEnvelopeJCS()
	// iat is not set in input

	signed, err := SignEd25519(env, payload, priv, true)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.Iat == nil {
		t.Fatalf("iat should be set")
	}

	if err := VerifyEd25519(signed, pub); err != nil {
		t.Fatalf("verify sig: %v", err)
	}
}

func TestV1_Verify_IatTampered_Fails(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"a":1,"b":2}`)
	env := baseEnvelopeJCS()

	signed, err := SignEd25519(env, payload, priv, true)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.Iat == nil {
		t.Fatalf("iat should be set")
	}

	// Tamper iat
	v := *signed.Iat
	v++
	signed.Iat = &v

	if err := VerifyEd25519(signed, pub); err == nil {
		t.Fatalf("want verify failure after tampering iat, got nil")
	}
}

func TestV1_NewTimeseriesEnvelopeTemplateV1_OK(t *testing.T) {
	env, err := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	if err != nil {
		t.Fatalf("NewTimeseriesEnvelopeTemplateV1: %v", err)
	}

	if env.V != Version1 {
		t.Fatalf("v mismatch: got %d", env.V)
	}
	if env.Alg != V1AlgEd25519 {
		t.Fatalf("alg mismatch: got %q", env.Alg)
	}
	if env.Kid != "demo-1" {
		t.Fatalf("kid mismatch: got %q", env.Kid)
	}
	if env.PayloadEncoding != V1PayloadEncodingJCS {
		t.Fatalf("payload_encoding mismatch: got %q", env.PayloadEncoding)
	}
	if env.PayloadHashAlg != V1PayloadHashAlgSHA256 {
		t.Fatalf("payload_hash_alg mismatch: got %q", env.PayloadHashAlg)
	}

	if env.TsSessionID == nil || *env.TsSessionID == "" {
		t.Fatalf("ts_session_id should be set")
	}
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRe.MatchString(*env.TsSessionID) {
		t.Fatalf("ts_session_id should look like uuid v4, got %q", *env.TsSessionID)
	}

	if env.TsSeq == nil {
		t.Fatalf("ts_seq should be set")
	}
	if *env.TsSeq != 0 {
		t.Fatalf("ts_seq should be 0, got %d", *env.TsSeq)
	}

	if env.TsPrev != nil {
		t.Fatalf("ts_prev must be omitted for seq=0, got %v", *env.TsPrev)
	}
}
