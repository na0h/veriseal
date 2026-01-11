package core

type Envelope struct {
	V   int    `json:"v"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`

	// PayloadEncoding declares how the payload hash was computed.
	// - "JCS": payload is JSON and the hash is computed over JCS(payload) bytes.
	// - "raw": payload is treated as raw bytes.
	PayloadEncoding string `json:"payload_encoding"`

	PayloadHashAlg string `json:"payload_hash_alg"`
	PayloadHash    string `json:"payload_hash,omitempty"`

	Sig *string `json:"sig,omitempty"`
}
