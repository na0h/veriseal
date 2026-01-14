package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/na0h/veriseal/canonical"
	testutil "github.com/na0h/veriseal/internal"
)

func goldenPath(parts ...string) string {
	all := append([]string{"testdata", "golden"}, parts...)
	return filepath.Join(all...)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	b = append(b, '\n')
	return b
}

func TestGolden_SignBasic(t *testing.T) {
	// deterministic iat
	oldNowUnix := nowUnix
	nowUnix = func() int64 { return 1700000000 }
	t.Cleanup(func() { nowUnix = oldNowUnix })

	// deterministic ed25519 keypair (sign is deterministic for fixed msg+key)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// fixed payload
	payload := []byte("{\"hello\":\"world\",\"n\":1}\n")

	env, err := NewEnvelopeTemplateV1("test-kid", "jcs")
	if err != nil {
		t.Fatalf("NewEnvelopeTemplateV1: %v", err)
	}

	signed, err := SignEd25519(env, payload, priv, true)
	if err != nil {
		t.Fatalf("SignEd25519: %v", err)
	}

	// unsigned canonical + hash
	unsigned := signed
	unsigned.Sig = nil

	b, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatalf("json marshal unsigned: %v", err)
	}
	canonBytes, err := canonical.Canonicalize(b)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	testutil.DiffOrUpdate(t, goldenPath("sign", "basic", "envelope.unsigned.canon.json"), append(canonBytes, '\n'))

	sum := sha256.Sum256(canonBytes)
	hashB64 := base64.StdEncoding.EncodeToString(sum[:])
	testutil.DiffOrUpdate(t, goldenPath("sign", "basic", "envelope.unsigned.hash.b64"), []byte(hashB64+"\n"))

	testutil.DiffOrUpdate(t, goldenPath("sign", "basic", "envelope.signed.json"), mustJSON(t, signed))
}

func TestGolden_TimeseriesBasic(t *testing.T) {
	// deterministic session id
	oldUUID := newUUIDv4Func
	newUUIDv4Func = func() (string, error) { return "00000000-0000-4000-8000-000000000000", nil }
	t.Cleanup(func() { newUUIDv4Func = oldUUID })

	env0, err := NewTimeseriesEnvelopeTemplateV1("test-kid", "jcs")
	if err != nil {
		t.Fatalf("NewTimeseriesEnvelopeTemplateV1: %v", err)
	}
	testutil.DiffOrUpdate(t, goldenPath("ts", "basic", "seq0.template.json"), mustJSON(t, env0))

	env1, err := NextTimeseriesEnvelopeTemplateV1(env0)
	if err != nil {
		t.Fatalf("NextTimeseriesEnvelopeTemplateV1: %v", err)
	}
	testutil.DiffOrUpdate(t, goldenPath("ts", "basic", "seq1.template.json"), mustJSON(t, env1))

	// Freeze unsigned canonical + hash for seq0 and seq1 (this defines ts_prev link behavior).
	var seq0HashB64 string

	{
		u0 := env0
		u0.Sig = nil
		b0, err := json.Marshal(u0)
		if err != nil {
			t.Fatalf("json marshal env0 unsigned: %v", err)
		}
		c0, err := canonical.Canonicalize(b0)
		if err != nil {
			t.Fatalf("canonicalize env0: %v", err)
		}
		testutil.DiffOrUpdate(t, goldenPath("ts", "basic", "seq0.unsigned.canon.json"), append(c0, '\n'))

		sum0 := sha256.Sum256(c0)
		seq0HashB64 = base64.StdEncoding.EncodeToString(sum0[:])
		testutil.DiffOrUpdate(t, goldenPath("ts", "basic", "seq0.unsigned.hash.b64"), []byte(seq0HashB64+"\n"))
	}

	{
		u1 := env1
		u1.Sig = nil
		b1, err := json.Marshal(u1)
		if err != nil {
			t.Fatalf("json marshal env1 unsigned: %v", err)
		}
		c1, err := canonical.Canonicalize(b1)
		if err != nil {
			t.Fatalf("canonicalize env1: %v", err)
		}
		testutil.DiffOrUpdate(t, goldenPath("ts", "basic", "seq1.unsigned.canon.json"), append(c1, '\n'))

		sum1 := sha256.Sum256(c1)
		seq1HashB64 := base64.StdEncoding.EncodeToString(sum1[:])
		testutil.DiffOrUpdate(t, goldenPath("ts", "basic", "seq1.unsigned.hash.b64"), []byte(seq1HashB64+"\n"))
	}

	if env1.TsPrev == nil || *env1.TsPrev != seq0HashB64 {
		t.Fatalf("ts_prev mismatch: want %s, got %v", seq0HashB64, env1.TsPrev)
	}

	// should pass in both modes
	if err := AuditTimeseriesV1([]Envelope{env0, env1}, true); err != nil {
		t.Fatalf("AuditTimeseriesV1 strict: %v", err)
	}
	if err := AuditTimeseriesV1([]Envelope{env0, env1}, false); err != nil {
		t.Fatalf("AuditTimeseriesV1 non-strict: %v", err)
	}
}
