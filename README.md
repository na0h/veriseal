# VeriSeal

VeriSeal is a minimal toolkit for handling **verifiable data** using signatures and hashes.

[日本語版 README](README.ja.md)

## License

Apache License 2.0

---

## Concept

VeriSeal does not handle the data itself.
It handles metadata that enables verification that the data has not been tampered with.

- An Envelope stores only the payload hash and the signature
- The payload is provided externally at verification time

---

## Envelope v1

### Unsigned Template

```json
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "demo-1",
  "payload_encoding": "jcs",
  "payload_hash_alg": "SHA-256"
}
```

### Signed Envelope

```json
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "demo-1",
  "payload_encoding": "jcs",
  "payload_hash_alg": "SHA-256",
  "payload_hash": "BASE64...",
  "sig": "BASE64..."
}
```

### Field Description

- `v`
  - Envelope version (fixed to v1)

- `alg`
  - Signature algorithm
  - v1 supports `Ed25519` only

- `kid`
  - Key identifier (Key ID)

- `iat`
  - Issued-at time (UNIX timestamp)
  - Optional

- `payload_encoding`
  - Payload normalization method

- `payload_hash_alg`
  - Payload hash algorithm
  - v1 supports `SHA-256` only

- `payload_hash`
  - Base64-encoded SHA-256 hash of normalized payload bytes

- `sig`
  - Signature value (Base64)

### Timeseries (Optional)

- `ts_session_id`
  - Identifier representing a continuity session (UUID)
  - Optional

- `ts_seq`
  - Sequence number within a `ts_session_id`
  - Non-negative integer (recommended: uint64)
  - Must monotonically increase within the session
  - An error should be raised if continuation is not possible due to overflow
  - If `ts_seq = 0`, `ts_prev` must not exist

- `ts_prev`
  - Base64-encoded SHA-256 hash of the previous Envelope JSON with the `sig` field excluded
  - Optional
  - Required when `ts_seq > 0`

---

## payload_encoding (v1)

### jcs

- Payload must be JSON
- JSON key order and whitespace differences do not affect the hash

### raw

- Payload is treated as arbitrary bytes
- Character encoding changes, newline normalization, recompression, etc. must not be performed

---

## Signing and Verification Model

The signature is computed over the entire Envelope including `payload_hash`.
Verification of `payload_hash` and verification of the signature are independent operations.

---

## CLI

### init

Outputs an Envelope v1 JSON template.

```sh
go run ./cmd/veriseal init \
  --kid demo-1 \
  --payload-encoding jcs \
  --output envelope.template.json
```

```json
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "demo-1",
  "payload_encoding": "jcs",
  "payload_hash_alg": "SHA-256"
}
```

### sign

Reads a payload and signs an Envelope.

```sh
go run ./cmd/veriseal sign \
  --privkey privkey.pem \
  --input envelope.template.json \
  --payload-file payload.json \
  --output envelope.signed.json
```

To attach an issued-at timestamp (`iat`, UNIX time), specify `--set-iat`.

```sh
go run ./cmd/veriseal sign \
  --privkey privkey.pem \
  --input envelope.template.json \
  --payload-file payload.json \
  --output envelope.signed.json \
  --set-iat
```

### verify

Verifies the signature.
If a payload is provided, `payload_hash` is also verified.

```sh
go run ./cmd/veriseal verify \
  --pubkey pubkey.pem \
  --input envelope.signed.json

go run ./cmd/veriseal verify \
  --pubkey pubkey.pem \
  --input envelope.signed.json \
  --payload-file payload.json
```

---

## Timeseries

Timeseries provides auxiliary commands to verify Envelope continuity
(missing entries, reordering, branching).

### ts init

Starts a new timeseries session.

```sh
go run ./cmd/veriseal ts init \
  --kid demo-1 \
  --payload-encoding jcs \
  --output envelope.template.json
```

- Generates a new `ts_session_id`
- Sets `ts_seq = 0`
- Does not set `ts_prev`
- Outputs an unsigned Envelope template

### ts next

Generates the next Envelope template based on the previous signed Envelope.

```sh
go run ./cmd/veriseal ts next \
  --prev envelope.prev.signed.json \
  --output envelope.template.json
```

- `ts_session_id` is inherited from the previous Envelope
- `ts_seq = prev.ts_seq + 1`
- `ts_prev` is calculated as the Base64-encoded SHA-256 hash of the previous unsigned Envelope
- Outputs an unsigned Envelope template

### ts check

Checks continuity between two Envelopes.
Intended mainly for immediate checks during ingestion.

```sh
go run ./cmd/veriseal ts check \
  --prev prev.signed.json \
  --current current.signed.json
```

### ts audit

Verifies continuity across multiple Envelopes.
Does not perform signature or payload verification.

```sh
go run ./cmd/veriseal ts audit \
  --input envelopes.jsonl
```

Checks:

- `ts_session_id` is consistent
- `ts_seq` monotonically increases from 0
- `ts_prev` matches the previous Envelope

---

## Key Formats

- Private key: Ed25519 / PKCS#8 PEM (`BEGIN PRIVATE KEY`)
- Public key: Ed25519 / SPKI PEM (`BEGIN PUBLIC KEY`)

```sh
# private (PKCS#8 PEM)
openssl genpkey \
  -algorithm ED25519 \
  -out privkey.pem

# public (SPKI PEM)
openssl pkey \
  -in privkey.pem \
  -pubout \
  -out pubkey.pem
```
