package core

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
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

func NewTimeseriesEnvelopeTemplateV1(kid string, payloadEncoding string) (Envelope, error) {
	env, err := NewEnvelopeTemplateV1(kid, payloadEncoding)
	if err != nil {
		return Envelope{}, err
	}

	sid, err := newUUIDv4()
	if err != nil {
		return Envelope{}, err
	}
	seq := uint64(0)
	env.TsSessionID = &sid

	env.TsSeq = &seq
	return env, nil
}

func newUUIDv4() (string, error) {
	u, err := uuid.NewRandom() // crypto/rand 使用
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
