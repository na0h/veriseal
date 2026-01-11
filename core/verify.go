package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/na0h/veriseal/canonical"
)

func NormalizePayloadBytes(payload []byte, payloadEncoding string) ([]byte, error) {
	switch payloadEncoding {
	case "":
		return nil, fmt.Errorf("missing payload_encoding")
	case V1PayloadEncodingRaw:
		return payload, nil
	case V1PayloadEncodingJCS:
		b, err := canonical.Canonicalize(payload)
		if err != nil {
			return nil, fmt.Errorf("payload_encoding=JCS but payload is not valid JSON")
		}
		return b, nil
	default:
		return nil, fmt.Errorf("unsupported payload_encoding: %s", payloadEncoding)
	}
}

func ComputePayloadHash(payload []byte, payloadEncoding string) (string, error) {
	norm, err := NormalizePayloadBytes(payload, payloadEncoding)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(norm)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func VerifyPayloadHash(envelope Envelope, payloadBytes []byte) error {
	if envelope.PayloadHash == "" {
		return fmt.Errorf("missing payload_hash")
	}

	want, err := ComputePayloadHash(payloadBytes, envelope.PayloadEncoding)
	if err != nil {
		return err
	}
	if envelope.PayloadHash != want {
		return fmt.Errorf("payload hash mismatch")
	}
	return nil
}

func VerifyEd25519(envelope Envelope, pub ed25519.PublicKey) error {
	if err := ValidateEnvelopeV1(envelope); err != nil {
		return err
	}
	if err := ValidateEnvelopeV1ForVerify(envelope); err != nil {
		return err
	}

	s := envelope.Sig
	sig, err := base64.StdEncoding.DecodeString(*s)
	if err != nil {
		return fmt.Errorf("invalid sig (base64 decode failed)")
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid sig size")
	}

	unsigned := envelope
	unsigned.Sig = nil

	b, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	msg, err := canonical.Canonicalize(b)
	if err != nil {
		return err
	}

	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
