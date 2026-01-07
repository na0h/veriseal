package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/na0h/veriseal/canonical"
)

func SignEd25519V1(envelope Envelope, payloadBytes []byte, priv ed25519.PrivateKey) (Envelope, error) {

	if envelope.V != 1 {
		return Envelope{}, fmt.Errorf("v1: invalid v=%d (expected 1)", envelope.V)
	}
	if envelope.Alg != V1AlgEd25519 {
		return Envelope{}, errors.New("v1: unsupported alg: " + envelope.Alg)
	}
	if envelope.Kid == "" {
		return Envelope{}, errors.New("v1: missing kid")
	}
	if envelope.PayloadEncoding == "" {
		return Envelope{}, errors.New("v1: missing payload_encoding")
	}
	if envelope.PayloadEncoding != V1PayloadEncodingJCS && envelope.PayloadEncoding != V1PayloadEncodingRaw {
		return Envelope{}, errors.New("v1: unsupported payload_encoding: " + envelope.PayloadEncoding)
	}
	if envelope.PayloadHashAlg != V1PayloadHashAlgSHA256 {
		return Envelope{}, errors.New("v1: unsupported payload_hash_alg: " + envelope.PayloadHashAlg)
	}

	h, err := ComputePayloadHashV1(payloadBytes, envelope.PayloadEncoding)
	if err != nil {
		return Envelope{}, err
	}
	envelope.PayloadHash = h

	unsigned := envelope
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
	envelope.Sig = base64.StdEncoding.EncodeToString(sig)
	return envelope, nil
}
