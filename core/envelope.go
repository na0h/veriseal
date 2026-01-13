package core

type Envelope struct {
	V   int    `json:"v"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`

	// Iat is the issued-at time (epoch seconds). Optional.
	Iat *int64 `json:"iat,omitempty"`

	TsSessionID *string `json:"ts_session_id,omitempty"`
	TsSeq       *uint64 `json:"ts_seq,omitempty"`
	TsPrev      *string `json:"ts_prev,omitempty"`

	// PayloadEncoding declares how the payload hash was computed.
	// - "jcs": payload is JSON and the hash is computed over jcs(payload) bytes.
	// - "raw": payload is treated as raw bytes.
	PayloadEncoding string `json:"payload_encoding"`

	PayloadHashAlg string `json:"payload_hash_alg"`
	PayloadHash    string `json:"payload_hash,omitempty"`

	Sig *string `json:"sig,omitempty"`
}
