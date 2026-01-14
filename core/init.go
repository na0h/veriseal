package core

import (
	"fmt"
	"strings"
)

func NewEnvelopeTemplateV1(kid string, payloadEncoding string) (Envelope, error) {
	if strings.TrimSpace(kid) == "" {
		return Envelope{}, fmt.Errorf("kid is required")
	}
	if payloadEncoding != V1PayloadEncodingJCS && payloadEncoding != V1PayloadEncodingRaw {
		return Envelope{}, fmt.Errorf("invalid payloadEncoding: %s", payloadEncoding)
	}

	env := Envelope{
		V:               Version1,
		Alg:             V1AlgEd25519,
		Kid:             kid,
		PayloadEncoding: payloadEncoding,
		PayloadHashAlg:  V1PayloadHashAlgSHA256,
	}
	return env, nil
}
