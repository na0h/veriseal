# VeriSeal

VeriSeal は、署名とハッシュにより「検証可能なデータ（Verifiable Data）」を扱うための最小ツールキットです。

- EdgeGW やサーバーを信頼しない前提
- クラウドは保存・転送のみ（信頼点にしない）
- 第三者・後段システムが独立して検証できることを重視

## Envelope v1

```json
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "demo-1",
  "payload_type": "application/json",
  "payload_encoding": "JCS",
  "payload_hash_alg": "SHA-256",
  "payload_hash": "BASE64...",
  "sig": "BASE64..."
}
```

### payload_encoding（v1 必須）

- `JCS`: payload は JSON。`payload_hash = SHA-256( JCS(payload) bytes )`
- `raw`: payload は bytes。`payload_hash = SHA-256(payload bytes)`

## 通信モデル

### モードA: JSON-only（推奨）

- `Content-Type: application/json`
- body: `{ envelope, payload }`
- Envelope: `payload_encoding = "JCS"`

### モードB: multipart（binary 推奨）

- `Content-Type: multipart/form-data`
- parts:
  - `envelope`（`application/json`）
  - `payload`（任意の bytes）
- Envelope: `payload_encoding = "raw"`

hash 対象は **payload part の body bytes のみ**（multipart の境界やヘッダ等は含めない）。
中継・保存は payload bytes を変更しないこと（改行変換・再圧縮・charset 変換などをしない）。

### モードC: JSON + base64（フォールバック）

- `Content-Type: application/json`
- body: `{ envelope, payload_b64 }`
- Envelope: `payload_encoding = "raw"`

## CLI

### sign

`payload_encoding` に応じて payload hash を計算し、Envelope を署名します。

```sh
veriseal sign --privkey ./privkey --input envelope.json --payload-file payload.json --payload-encoding JCS --output envelope.signed.json
veriseal sign --privkey ./privkey --input envelope.json --payload-file payload.bin --payload-encoding raw --output envelope.signed.json
```

### verify

payload を渡すと payload hash まで検証します。

```sh
veriseal verify --pubkey ./pubkey --input envelope.signed.json
veriseal verify --pubkey ./pubkey --input envelope.signed.json --payload-file payload.bin
```
