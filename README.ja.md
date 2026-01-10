# VeriSeal

VeriSeal は、署名とハッシュにより **検証可能なデータ（Verifiable Data）** を扱うための最小ツールキットです。

## License

Apache License 2.0

---

## コンセプト

VeriSeal は「データそのもの」ではなく、**データが改ざんされていないことを検証可能にするためのメタ情報**を扱います。

- Envelope は payload のハッシュと署名のみを保持する
- payload は検証時に **外部から与える**

---

## Envelope v1

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

### フィールド説明

- `v`
  - Envelope バージョン（v1 固定）

- `alg`
  - 署名アルゴリズム
  - v1 では `Ed25519` のみ

- `kid`
  - 鍵識別子（Key ID）

- `payload_encoding`
  - payload の正規化方法

- `payload_hash_alg`
  - payload ハッシュアルゴリズム
  - v1 では `SHA-256` のみ

- `payload_hash`
  - 正規化後 payload bytes に対する SHA-256 の Base64 表現

- `sig`
  - 署名値（Base64）

---

## payload_encoding（v1）

### `JCS`

- payload は JSON
- JSON のキー順や空白差分は影響しない

### `raw`

- payload は任意の bytes
- 文字コード・改行変換・再圧縮などを行ってはならない

---

## 署名・検証モデル

署名は payload_hash を含む Envelope 全体に対して行われ、payload_hash の検証と署名検証は独立して実行可能である。

---

## CLI

### sign

payload を読み込み、Envelope に署名します。

```sh
veriseal sign \
  --privkey privkey.pem \
  --input envelope.json \
  --payload-file payload.json \
  --output envelope.signed.json
```

```json
// envelope.json sample
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "demo-1",
  "payload_encoding": "JCS",
  "payload_hash_alg": "SHA-256",
  "payload_hash": "",
  "sig": ""
}
```

### verify

署名検証を行います。payload を指定した場合は payload_hash も検証します。

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

## 鍵形式

- 秘密鍵: Ed25519 / PKCS#8 PEM（`BEGIN PRIVATE KEY`）
- 公開鍵: Ed25519 / SPKI PEM（`BEGIN PUBLIC KEY`）

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

