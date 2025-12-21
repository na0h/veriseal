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
)

// ComputePayloadHashV1 computes base64(SHA-256(payloadBytes)).
func ComputePayloadHashV1(payload []byte) (string, error) {
	sum := sha256.Sum256(payload)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func SignEd25519V1(env EnvelopeV1, payloadBytes []byte, priv ed25519.PrivateKey) (EnvelopeV1, error) {
	// defaults / validation
	if env.V == 0 {
		env.V = 1
	}
	if env.V != 1 {
		return EnvelopeV1{}, fmt.Errorf("v1: invalid v=%d (expected 1)", env.V)
	}
	if env.Alg == "" {
		env.Alg = V1AlgEd25519
	}
	if env.Alg != V1AlgEd25519 {
		return EnvelopeV1{}, errors.New("v1: unsupported alg: " + env.Alg)
	}
	if env.Kid == "" {
		return EnvelopeV1{}, errors.New("v1: missing kid")
	}
	if env.PayloadType == "" {
		env.PayloadType = "application/octet-stream"
	}
	if env.PayloadHashAlg == "" {
		env.PayloadHashAlg = V1PayloadHashAlgSHA256
	}
	if env.PayloadHashAlg != V1PayloadHashAlgSHA256 {
		return EnvelopeV1{}, errors.New("v1: unsupported payload_hash_alg: " + env.PayloadHashAlg)
	}

	h, err := ComputePayloadHashV1(payloadBytes)
	if err != nil {
		return EnvelopeV1{}, err
	}
	env.PayloadHash = h

	unsigned := env
	unsigned.Sig = ""

	b, err := json.Marshal(unsigned)
	if err != nil {
		return EnvelopeV1{}, err
	}
	msg, err := canonical.Canonicalize(b)
	if err != nil {
		return EnvelopeV1{}, err
	}

	sig := ed25519.Sign(priv, msg)
	env.Sig = base64.StdEncoding.EncodeToString(sig)
	return env, nil
}

// VerifyEd25519V1 verifies the signature. If payloadBytes is non-nil,
// it also verifies payload hash matches payloadBytes.
func VerifyEd25519V1(env EnvelopeV1, pub ed25519.PublicKey, payloadBytes []byte) error {
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
		want, err := ComputePayloadHashV1(payloadBytes)
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
