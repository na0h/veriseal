package core

import (
	"fmt"
	"math"
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
	sig := envelope.Sig
	if sig == nil || *sig == "" {
		return fmt.Errorf("missing sig")
	}
	return nil
}

func ValidateTimeseriesPrevForNext(prev Envelope) error {
	if prev.V != Version1 {
		return fmt.Errorf("unsupported v: %d", prev.V)
	}
	if prev.TsSessionID == nil || *prev.TsSessionID == "" {
		return fmt.Errorf("missing ts_session_id in previous envelope")
	}
	if prev.TsSeq == nil {
		return fmt.Errorf("missing ts_seq in previous envelope")
	}
	if *prev.TsSeq == math.MaxUint64 {
		return fmt.Errorf("ts_seq overflow: reached max uint64")
	}
	return nil
}

func ValidateTimeseriesCurrForCheck(curr Envelope) error {
	if curr.V != Version1 {
		return fmt.Errorf("unsupported v: %d", curr.V)
	}
	if curr.TsSessionID == nil || *curr.TsSessionID == "" {
		return fmt.Errorf("missing ts_session_id")
	}
	if curr.TsSeq == nil {
		return fmt.Errorf("missing ts_seq")
	}
	if curr.TsPrev == nil || *curr.TsPrev == "" {
		return fmt.Errorf("missing ts_prev")
	}
	return nil
}
