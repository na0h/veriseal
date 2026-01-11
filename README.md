# VeriSeal

VeriSeal is a minimal toolkit for handling **verifiable data** using signatures and hashes.

[日本語版 README](README.ja.md)

## License

Apache License 2.0

---

## Concept

VeriSeal does not handle the data itself. Instead, it handles **metadata that enables verification that data has not been tampered with**.

- An Envelope contains only a hash of the payload and a signature
- The payload itself is provided **externally at verification time**

---

## Envelope v1

**Unsigned template**
```json
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "demo-1",
  "payload_encoding": "JCS",
  "payload_hash_alg": "SHA-256"
}
```

**Signed envelope**
```json
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "demo-1",
  "payload_encoding": "JCS",
  "payload_hash_alg": "SHA-256",
  "payload_hash": "BASE64...",
  "sig": "BASE64..."
}
```

### Fields

- `v`
  - Envelope version (fixed to v1)

- `alg`
  - Signature algorithm
  - v1 supports `Ed25519` only

- `kid`
  - Key identifier (Key ID)

- `iat`
  - Issued At (UNIX time, seconds)
  - Optional
  - Included in the signature when present

- `payload_encoding`
  - Normalization method applied to the payload

- `payload_hash_alg`
  - Payload hash algorithm
  - v1 supports `SHA-256` only

- `payload_hash`
  - Base64-encoded SHA-256 hash of normalized payload bytes

- `sig`
  - Signature value (Base64)

---

## payload_encoding (v1)

### `JCS`

- Payload must be JSON
- JSON key order and whitespace differences do not affect the hash

### `raw`

- Payload is treated as arbitrary bytes
- Character encoding changes, newline conversions, or recompression must not be performed

---

## Signing and Verification Model

The signature is computed over the entire Envelope including `payload_hash`.
Verification of `payload_hash` and verification of the signature are independent operations.

---

## CLI

### init

Prints an **Envelope v1 JSON template**.

```sh
veriseal init --kid demo-1 --payload-encoding JCS --output envelope.template.json
```

```json
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "demo-1",
  "payload_encoding": "JCS",
  "payload_hash_alg": "SHA-256"
}
```

### sign

Reads a payload and signs an Envelope.

```sh
veriseal sign \
  --privkey privkey.pem \
  --input envelope.template.json \
  --payload-file payload.json \
  --output envelope.signed.json
```

To attach an issuance timestamp (`iat`, UNIX time), specify `--set-iat`.

```sh
veriseal sign \
  --privkey privkey.pem \
  --input envelope.template.json \
  --payload-file payload.json \
  --output envelope.signed.json \
  --set-iat
```

If the input already contains `iat`, it will be overwritten and a warning will be printed.
```

### verify

Verifies a signature. If a payload is provided, `payload_hash` is also verified.

```sh
veriseal verify \
  --pubkey pubkey.pem \
  --input envelope.signed.json

veriseal verify \
  --pubkey pubkey.pem \
  --input envelope.signed.json \
  --payload-file payload.json
```

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

---
