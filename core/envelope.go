package core

type Envelope struct {
	V   int    `json:"v"`   // must be 1
	Alg string `json:"alg"` // "Ed25519"
	Kid string `json:"kid"`

	// PayloadEncoding declares how the payload hash was computed.
	// - "JCS": payload is JSON and the hash is computed over JCS(payload) bytes.
	// - "raw": payload is treated as raw bytes.
	PayloadEncoding string `json:"payload_encoding"`

	PayloadHashAlg string `json:"payload_hash_alg"` // "SHA-256"
	PayloadHash    string `json:"payload_hash"`     // base64(sha256(payloadBytes))
	PayloadType    string `json:"payload_type"`     // e.g. application/octet-stream

	Sig string `json:"sig,omitempty"` // base64(ed25519 signature)
}
