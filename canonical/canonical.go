package canonical

import (
	"errors"

	"github.com/gowebpki/jcs"
)

// Canonicalize は RFC8785 (JCS) に従って JSON を正規化し、署名対象 bytes を返す。
func Canonicalize(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, errors.New("empty input")
	}

	// JCS は「同じ意味のJSON」を決定論的に同一表現にするための規約
	out, err := jcs.Transform(input)
	if err != nil {
		return nil, err
	}
	return out, nil
}
