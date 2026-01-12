package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"math"
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

	// Same semantic JSON, but raw vs jcs normalization must not be mixed.
	rawPayload := []byte(`{"a":1,"b":2}`)
	jcsPayload := []byte(`{"b":2,"a":1}`)

	env := baseEnvelopeRaw()
	signed, err := SignEd25519(env, rawPayload, priv, false)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify payload hash with jcs payload must fail because encoding differs.
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

func TestV1_NextTimeseriesEnvelopeTemplateV1_OK(t *testing.T) {
	prev, err := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	if err != nil {
		t.Fatalf("NewTimeseriesEnvelopeTemplateV1: %v", err)
	}

	sig := "dummy"
	prev.Sig = &sig
	prev.PayloadHash = "dummyhash"

	next, err := NextTimeseriesEnvelopeTemplateV1(prev)
	if err != nil {
		t.Fatalf("NextTimeseriesEnvelopeTemplateV1: %v", err)
	}

	if next.TsSessionID == nil || prev.TsSessionID == nil || *next.TsSessionID != *prev.TsSessionID {
		t.Fatalf("ts_session_id should be inherited")
	}
	if next.TsSeq == nil || prev.TsSeq == nil || *next.TsSeq != *prev.TsSeq+1 {
		t.Fatalf("ts_seq should increment")
	}
	if next.TsPrev == nil || *next.TsPrev == "" {
		t.Fatalf("ts_prev should be set")
	}
	if next.Sig != nil {
		t.Fatalf("next template must not include sig")
	}
	if next.PayloadHash != "" {
		t.Fatalf("next template must not include payload_hash")
	}
}

func TestV1_NextTimeseriesEnvelopeTemplateV1_PrevHashIsIndependentOfSig(t *testing.T) {
	prev, _ := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	prev.PayloadHash = "dummyhash"

	sig1 := "sig1"
	prev.Sig = &sig1
	next1, err := NextTimeseriesEnvelopeTemplateV1(prev)
	if err != nil {
		t.Fatal(err)
	}

	sig2 := "sig2"
	prev.Sig = &sig2
	next2, err := NextTimeseriesEnvelopeTemplateV1(prev)
	if err != nil {
		t.Fatal(err)
	}

	if *next1.TsPrev != *next2.TsPrev {
		t.Fatalf("ts_prev must not depend on sig")
	}
}

func TestV1_NextTimeseriesEnvelopeTemplateV1_PrevHashDependsOnPayloadHash(t *testing.T) {
	prev, _ := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)

	prev.PayloadHash = "h1"
	next1, err := NextTimeseriesEnvelopeTemplateV1(prev)
	if err != nil {
		t.Fatal(err)
	}

	prev.PayloadHash = "h2"
	next2, err := NextTimeseriesEnvelopeTemplateV1(prev)
	if err != nil {
		t.Fatal(err)
	}

	if *next1.TsPrev == *next2.TsPrev {
		t.Fatalf("ts_prev must depend on payload_hash")
	}
}

func TestV1_ValidateTimeseriesPrevForNext_Overflow(t *testing.T) {
	prev, _ := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	max := uint64(math.MaxUint64)
	prev.TsSeq = &max

	if err := ValidateTimeseriesPrevForNext(prev); err == nil {
		t.Fatalf("want overflow error, got nil")
	}
}

func TestV1_CheckTimeseriesLinkV1_OK(t *testing.T) {
	prev, err := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	if err != nil {
		t.Fatalf("NewTimeseriesEnvelopeTemplateV1: %v", err)
	}

	// prev の unsigned hash 計算に入る要素を適当に埋める
	prev.PayloadHash = "dummyhash"
	sig := "dummy"
	prev.Sig = &sig

	curr, err := NextTimeseriesEnvelopeTemplateV1(prev)
	if err != nil {
		t.Fatalf("NextTimeseriesEnvelopeTemplateV1: %v", err)
	}

	if err := CheckTimeseriesLinkV1(prev, curr); err != nil {
		t.Fatalf("CheckTimeseriesLinkV1: %v", err)
	}
}

func TestV1_CheckTimeseriesLinkV1_TsPrevMismatch(t *testing.T) {
	prev, err := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	if err != nil {
		t.Fatalf("NewTimeseriesEnvelopeTemplateV1: %v", err)
	}
	prev.PayloadHash = "dummyhash"
	sig := "dummy"
	prev.Sig = &sig

	curr, err := NextTimeseriesEnvelopeTemplateV1(prev)
	if err != nil {
		t.Fatalf("NextTimeseriesEnvelopeTemplateV1: %v", err)
	}

	bad := "not-the-right-hash"
	curr.TsPrev = &bad

	if err := CheckTimeseriesLinkV1(prev, curr); err == nil {
		t.Fatalf("want error, got nil")
	}
}

func TestV1_CheckTimeseriesLinkV1_SeqMismatch(t *testing.T) {
	prev, _ := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	prev.PayloadHash = "dummyhash"

	curr, _ := NextTimeseriesEnvelopeTemplateV1(prev)
	seq := uint64(999)
	curr.TsSeq = &seq

	if err := CheckTimeseriesLinkV1(prev, curr); err == nil {
		t.Fatalf("want error, got nil")
	}
}

func TestV1_AuditTimeseriesV1_OK(t *testing.T) {
	e0, err := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	if err != nil {
		t.Fatalf("NewTimeseriesEnvelopeTemplateV1: %v", err)
	}

	e0.PayloadHash = "dummyhash"
	sig := "dummy"
	e0.Sig = &sig

	e1, err := NextTimeseriesEnvelopeTemplateV1(e0)
	if err != nil {
		t.Fatalf("NextTimeseriesEnvelopeTemplateV1(e0): %v", err)
	}
	e1.PayloadHash = "dummyhash1"
	e1.Sig = &sig

	e2, err := NextTimeseriesEnvelopeTemplateV1(e1)
	if err != nil {
		t.Fatalf("NextTimeseriesEnvelopeTemplateV1(e1): %v", err)
	}

	if err := AuditTimeseriesV1([]Envelope{e0, e1, e2}, false); err != nil {
		t.Fatalf("AuditTimeseriesV1: %v", err)
	}

	// strict-start でも通る（e0 は seq=0, ts_prev=nil のはず）
	if err := AuditTimeseriesV1([]Envelope{e0, e1, e2}, true); err != nil {
		t.Fatalf("AuditTimeseriesV1(strict): %v", err)
	}
}

func TestV1_AuditTimeseriesV1_FailAtIndex(t *testing.T) {
	e0, _ := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	sig := "dummy"
	e0.Sig = &sig
	e0.PayloadHash = "dummyhash"

	e1, _ := NextTimeseriesEnvelopeTemplateV1(e0)
	bad := "broken"
	e1.TsPrev = &bad

	err := AuditTimeseriesV1([]Envelope{e0, e1}, false)
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if !strings.Contains(err.Error(), "index 1") {
		t.Fatalf("want error containing %q, got %v", "index 1", err)
	}
}

func TestV1_AuditTimeseriesV1_AllowsNonZeroStartWhenNotStrict(t *testing.T) {
	e0, _ := NewTimeseriesEnvelopeTemplateV1("demo-1", V1PayloadEncodingJCS)
	e0.PayloadHash = "dummyhash"
	sig := "dummy"
	e0.Sig = &sig

	e1, _ := NextTimeseriesEnvelopeTemplateV1(e0)
	e1.PayloadHash = "dummyhash1"
	e1.Sig = &sig

	seq10 := uint64(10)
	e0.TsSeq = &seq10

	seq11 := uint64(11)
	e1.TsSeq = &seq11

	h, err := UnsignedHashV1(e0)
	if err != nil {
		t.Fatalf("UnsignedHashV1: %v", err)
	}
	e1.TsPrev = &h

	if err := AuditTimeseriesV1([]Envelope{e0, e1}, false); err != nil {
		t.Fatalf("want OK, got %v", err)
	}

	if err := AuditTimeseriesV1([]Envelope{e0, e1}, true); err == nil {
		t.Fatalf("want error in strict mode, got nil")
	}
}
