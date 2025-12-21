package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/na0h/veriseal/canonical"
)

const (
	V1PayloadHashAlgSHA256 = "SHA-256"
	V1AlgEd25519           = "Ed25519"
	V1PayloadEncodingJCS   = "JCS"
	V1PayloadEncodingRaw   = "raw"
)

// NormalizePayloadBytesV1 returns the bytes that must be hashed according to payloadEncoding.
func NormalizePayloadBytesV1(payload []byte, payloadEncoding string) ([]byte, error) {
	switch payloadEncoding {
	case "":
		return nil, errors.New("v1: missing payload_encoding")
	case V1PayloadEncodingRaw:
		return payload, nil
	case V1PayloadEncodingJCS:
		// payload must be JSON bytes; normalize using JCS-equivalent canonicalization.
		b, err := canonical.Canonicalize(payload)
		if err != nil {
			return nil, errors.New("v1: payload_encoding=JCS but payload is not valid JSON")
		}
		return b, nil
	default:
		return nil, errors.New("v1: unsupported payload_encoding: " + payloadEncoding)
	}
}

// ComputePayloadHashV1 computes base64(SHA-256(normalizedPayloadBytes)).
func ComputePayloadHashV1(payload []byte, payloadEncoding string) (string, error) {
	norm, err := NormalizePayloadBytesV1(payload, payloadEncoding)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(norm)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// VerifyEd25519V1 verifies the signature. If payloadBytes is non-nil,
// it also verifies payload hash matches payloadBytes.
func VerifyEd25519V1(env Envelope, pub ed25519.PublicKey, payloadBytes []byte) error {
	if env.V != 1 {
		return fmt.Errorf("v1: invalid v=%d (expected 1)", env.V)
	}
	if env.Alg == "" {
		env.Alg = V1AlgEd25519
	}
	if env.Alg != V1AlgEd25519 {
		return errors.New("v1: unsupported alg: " + env.Alg)
	}
	if env.Kid == "" {
		return errors.New("v1: missing kid")
	}
	if env.PayloadEncoding == "" {
		return errors.New("v1: missing payload_encoding")
	}
	if env.PayloadEncoding != V1PayloadEncodingJCS && env.PayloadEncoding != V1PayloadEncodingRaw {
		return errors.New("v1: unsupported payload_encoding: " + env.PayloadEncoding)
	}
	if env.PayloadHashAlg == "" {
		env.PayloadHashAlg = V1PayloadHashAlgSHA256
	}
	if env.PayloadHashAlg != V1PayloadHashAlgSHA256 {
		return errors.New("v1: unsupported payload_hash_alg: " + env.PayloadHashAlg)
	}
	if env.PayloadHash == "" {
		return errors.New("v1: missing payload_hash")
	}
	if env.Sig == "" {
		return errors.New("v1: missing sig")
	}

	// optional payload hash verification
	if payloadBytes != nil {
		want, err := ComputePayloadHashV1(payloadBytes, env.PayloadEncoding)
		if err != nil {
			return err
		}
		if env.PayloadHash != want {
			return fmt.Errorf("v1: payload hash mismatch")
		}
	}

	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return errors.New("v1: invalid sig (base64 decode failed)")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("v1: invalid sig size")
	}

	unsigned := env
	unsigned.Sig = ""

	b, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	msg, err := canonical.Canonicalize(b)
	if err != nil {
		return err
	}

	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("v1: signature verification failed")
	}
	return nil
}
