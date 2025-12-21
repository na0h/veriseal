package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/na0h/veriseal/canonical"
)

func SignEd25519V1(env Envelope, payloadBytes []byte, priv ed25519.PrivateKey) (Envelope, error) {

	if env.V != 1 {
		return Envelope{}, fmt.Errorf("v1: invalid v=%d (expected 1)", env.V)
	}
	if env.Alg == "" {
		env.Alg = V1AlgEd25519
	}
	if env.Alg != V1AlgEd25519 {
		return Envelope{}, errors.New("v1: unsupported alg: " + env.Alg)
	}
	if env.Kid == "" {
		return Envelope{}, errors.New("v1: missing kid")
	}
	if env.PayloadType == "" {
		env.PayloadType = "application/octet-stream"
	}
	if env.PayloadEncoding == "" {
		return Envelope{}, errors.New("v1: missing payload_encoding")
	}
	if env.PayloadEncoding != V1PayloadEncodingJCS && env.PayloadEncoding != V1PayloadEncodingRaw {
		return Envelope{}, errors.New("v1: unsupported payload_encoding: " + env.PayloadEncoding)
	}
	if env.PayloadHashAlg == "" {
		env.PayloadHashAlg = V1PayloadHashAlgSHA256
	}
	if env.PayloadHashAlg != V1PayloadHashAlgSHA256 {
		return Envelope{}, errors.New("v1: unsupported payload_hash_alg: " + env.PayloadHashAlg)
	}

	h, err := ComputePayloadHashV1(payloadBytes, env.PayloadEncoding)
	if err != nil {
		return Envelope{}, err
	}
	env.PayloadHash = h

	unsigned := env
	unsigned.Sig = ""

	b, err := json.Marshal(unsigned)
	if err != nil {
		return Envelope{}, err
	}
	msg, err := canonical.Canonicalize(b)
	if err != nil {
		return Envelope{}, err
	}

	sig := ed25519.Sign(priv, msg)
	env.Sig = base64.StdEncoding.EncodeToString(sig)
	return env, nil
}
