package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/na0h/veriseal/canonical"
)

func newUUIDv4() (string, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

var newUUIDv4Func = newUUIDv4

func NewTimeseriesEnvelopeTemplateV1(kid string, payloadEncoding string) (Envelope, error) {
	env, err := NewEnvelopeTemplateV1(kid, payloadEncoding)
	if err != nil {
		return Envelope{}, err
	}

	sid, err := newUUIDv4Func()
	if err != nil {
		return Envelope{}, err
	}
	seq := uint64(0)
	env.TsSessionID = &sid

	env.TsSeq = &seq
	return env, nil
}

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

func AuditTimeseriesV1(envelopes []Envelope, strictStart bool) error {
	if len(envelopes) == 0 {
		return fmt.Errorf("empty input")
	}

	first := envelopes[0]
	if first.TsSessionID == nil || *first.TsSessionID == "" {
		return fmt.Errorf("index 0: missing ts_session_id")
	}
	if first.TsSeq == nil {
		return fmt.Errorf("index 0: missing ts_seq")
	}

	if strictStart {
		if *first.TsSeq != 0 {
			return fmt.Errorf("index 0: ts_seq must start from 0")
		}
		if first.TsPrev != nil {
			return fmt.Errorf("index 0: ts_prev must be empty")
		}
	}

	for i := 1; i < len(envelopes); i++ {
		prev := envelopes[i-1]
		curr := envelopes[i]
		if err := CheckTimeseriesLinkV1(prev, curr); err != nil {
			return fmt.Errorf("index %d: %w", i, err)
		}
	}
	return nil
}
