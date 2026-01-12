package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

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
