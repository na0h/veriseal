package core

import "encoding/json"

type Envelope struct {
	V       int             `json:"v"`
	Alg     string          `json:"alg"`
	Kid     string          `json:"kid"`
	Payload json.RawMessage `json:"payload"`
	Sig     string          `json:"sig,omitempty"`
}
