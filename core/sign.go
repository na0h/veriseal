package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/na0h/veriseal/canonical"
)

func SignEd25519(envelope Envelope, payloadBytes []byte, priv ed25519.PrivateKey) (Envelope, error) {
	if err := ValidateEnvelopeV1(envelope); err != nil {
		return Envelope{}, err
	}

	h, err := ComputePayloadHash(payloadBytes, envelope.PayloadEncoding)
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
