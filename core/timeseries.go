package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/na0h/veriseal/canonical"
)

func UnsignedHashV1(env Envelope) (string, error) {
	unsigned := env
	unsigned.Sig = nil

	b, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	msg, err := canonical.Canonicalize(b)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(msg)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func NextTimeseriesEnvelopeTemplateV1(prev Envelope) (Envelope, error) {
	if err := ValidateTimeseriesPrevForNext(prev); err != nil {
		return Envelope{}, err
	}

	prevHash, err := UnsignedHashV1(prev)
	if err != nil {
		return Envelope{}, err
	}

	next, err := NewEnvelopeTemplateV1(prev.Kid, prev.PayloadEncoding)
	if err != nil {
		return Envelope{}, err
	}

	sid := *prev.TsSessionID
	seq := *prev.TsSeq + 1

	next.TsSessionID = &sid
	next.TsSeq = &seq
	next.TsPrev = &prevHash

	next.Iat = nil
	return next, nil
}

func CheckTimeseriesLinkV1(prev, curr Envelope) error {
	if err := ValidateTimeseriesPrevForNext(prev); err != nil {
		return fmt.Errorf("prev invalid: %w", err)
	}

	if err := ValidateTimeseriesCurrForCheck(curr); err != nil {
		return fmt.Errorf("curr invalid: %w", err)
	}

	if *curr.TsSessionID != *prev.TsSessionID {
		return fmt.Errorf("ts_session_id mismatch")
	}

	if *curr.TsSeq != *prev.TsSeq+1 {
		return fmt.Errorf("ts_seq mismatch: want %d, got %d", *prev.TsSeq+1, *curr.TsSeq)
	}

	wantPrev, err := UnsignedHashV1(prev)
	if err != nil {
		return err
	}
	if *curr.TsPrev != wantPrev {
		return fmt.Errorf("ts_prev mismatch")
	}

	return nil
}
