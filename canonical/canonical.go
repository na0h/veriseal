package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Canonicalize normalizes JSON into a deterministic byte representation.
//
// NOTE: This is intended to be JCS-compatible for typical IoT payloads
// (objects/arrays/strings/bools/null/numbers) by decoding with UseNumber and
// re-encoding without whitespace and with stable map key ordering.
//
// It does not attempt advanced Unicode normalization beyond what Go's json
// encoder performs.
func Canonicalize(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("empty input")
	}

	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	// ensure there's no trailing non-whitespace
	if err := dec.Decode(new(any)); err == nil {
		return nil, errors.New("invalid json: trailing content")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}

	out, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return out, nil
}
