package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/na0h/veriseal/canonical"
)

func SignEd25519(envelope Envelope, payloadBytes []byte, priv ed25519.PrivateKey, setIat bool) (Envelope, error) {
	if err := ValidateEnvelopeV1(envelope); err != nil {
		return Envelope{}, err
	}

	h, err := ComputePayloadHash(payloadBytes, envelope.PayloadEncoding)
	if err != nil {
		return Envelope{}, err
	}
	envelope.PayloadHash = h

	unsigned := envelope
	unsigned.Sig = nil

	if setIat {
		iat := time.Now().Unix()
		unsigned.Iat = &iat
	}

	b, err := json.Marshal(unsigned)
	if err != nil {
		return Envelope{}, err
	}
	msg, err := canonical.Canonicalize(b)
	if err != nil {
		return Envelope{}, err
	}

	sig := ed25519.Sign(priv, msg)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	signed := unsigned
	signed.Sig = &sigB64

	return signed, nil
}
