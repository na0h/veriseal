package core

import (
	"fmt"
)

func ValidateEnvelopeV1(envelope Envelope) error {
	if envelope.V != Version1 {
		return fmt.Errorf("invalid version: %d", envelope.V)
	}
	if envelope.Alg != V1AlgEd25519 {
		return fmt.Errorf("unsupported alg: %s", envelope.Alg)
	}
	if envelope.Kid == "" {
		return fmt.Errorf("missing kid")
	}
	if envelope.PayloadEncoding == "" {
		return fmt.Errorf("missing payload_encoding")
	}
	if envelope.PayloadEncoding != V1PayloadEncodingJCS && envelope.PayloadEncoding != V1PayloadEncodingRaw {
		return fmt.Errorf("unsupported payload_encoding: %s", envelope.PayloadEncoding)
	}
	if envelope.PayloadHashAlg != V1PayloadHashAlgSHA256 {
		return fmt.Errorf("unsupported payload_hash_alg: %s", envelope.PayloadHashAlg)
	}
	return nil
}

func ValidateEnvelopeV1ForVerify(envelope Envelope) error {
	if envelope.PayloadHash == "" {
		return fmt.Errorf("missing payload_hash")
	}
	if envelope.Sig == "" {
		return fmt.Errorf("missing sig")
	}
	return nil
}
