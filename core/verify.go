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

func VerifyPayloadHash(envelope Envelope, payloadBytes []byte) error {
	if envelope.PayloadHash == "" {
		return errors.New("v1: missing payload_hash")
	}

	want, err := ComputePayloadHashV1(payloadBytes, envelope.PayloadEncoding)
	if err != nil {
		return err
	}
	if envelope.PayloadHash != want {
		return fmt.Errorf("v1: payload hash mismatch")
	}
	return nil
}

func VerifyEd25519V1(envelope Envelope, pub ed25519.PublicKey) error {
	if envelope.V != 1 {
		return fmt.Errorf("v1: invalid v=%d (expected 1)", envelope.V)
	}
	if envelope.Alg != V1AlgEd25519 {
		return errors.New("v1: unsupported alg: " + envelope.Alg)
	}
	if envelope.Kid == "" {
		return errors.New("v1: missing kid")
	}
	if envelope.PayloadEncoding == "" {
		return errors.New("v1: missing payload_encoding")
	}
	if envelope.PayloadEncoding != V1PayloadEncodingJCS && envelope.PayloadEncoding != V1PayloadEncodingRaw {
		return errors.New("v1: unsupported payload_encoding: " + envelope.PayloadEncoding)
	}
	if envelope.PayloadHashAlg != V1PayloadHashAlgSHA256 {
		return errors.New("v1: unsupported payload_hash_alg: " + envelope.PayloadHashAlg)
	}
	if envelope.PayloadHash == "" {
		return errors.New("v1: missing payload_hash")
	}
	if envelope.Sig == "" {
		return errors.New("v1: missing sig")
	}

	sig, err := base64.StdEncoding.DecodeString(envelope.Sig)
	if err != nil {
		return errors.New("v1: invalid sig (base64 decode failed)")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("v1: invalid sig size")
	}

	unsigned := envelope
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
