package canonical

import (
	"encoding/json"
	"errors"

	jcs "github.com/gowebpki/jcs"
)

var (
	ErrEmptyInput          = errors.New("empty input")
	ErrInvalidJSON         = errors.New("invalid json")
	ErrTopLevelNotObjArray = errors.New("top-level JSON must be object or array")
)

func Canonicalize(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrEmptyInput
	}

	var v any
	if err := json.Unmarshal(input, &v); err != nil {
		return nil, ErrInvalidJSON
	}

	switch v.(type) {
	case map[string]any, []any:
	default:
		return nil, ErrTopLevelNotObjArray
	}

	return jcs.Transform(input)
}
