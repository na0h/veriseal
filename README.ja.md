# VeriSeal

VeriSeal は、署名とハッシュにより 検証可能なデータ（Verifiable Data） を扱うための最小ツールキットです。

## License

Apache License 2.0

---

## コンセプト

VeriSeal は「データそのもの」ではなく、データが改ざんされていないことを検証可能にするためのメタ情報を扱います。

- Envelope は payload のハッシュと署名のみを保持する
- payload は検証時に外部から与える

---

## Envelope v1

### 著名前テンプレート

```json
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "demo-1",
  "payload_encoding": "JCS",
  "payload_hash_alg": "SHA-256"
}
```

### 署名済み

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

- `iat`
  - 署名発行日時（UNIX時間）
  - Optional

- `payload_encoding`
  - payload の正規化方法

- `payload_hash_alg`
  - payload ハッシュアルゴリズム
  - v1 では `SHA-256` のみ

- `payload_hash`
  - 正規化後 payload bytes に対する SHA-256 の Base64 表現

- `sig`
  - 署名値（Base64）

#### Timeseries（Optional）

- `ts_session_id`
  - 連続性の単位を表す識別子（UUID）
  - Optional

- `ts_seq`
  - `ts_session_id` 内での連番
  - 非負整数（推奨: uint64）
  - `ts_session_id` 内で単調増加する
  - overflow 等で継続できない場合はエラーとする
  - `ts_seq = 0` の場合、`ts_prev` は存在してはならない

- `ts_prev`
  - 直前の Envelope から `sig` フィールドを除外したEnvelope JSON に対する SHA-256 ハッシュの Base64 表現
  - Optional
  - `ts_seq > 0` の場合は必須

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

### init

- Envelope v1 の JSON テンプレートを出力します。

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

- payload を読み込み、Envelope に署名します。

```sh
veriseal sign \
  --privkey privkey.pem \
  --input envelope.template.json \
  --payload-file payload.json \
  --output envelope.signed.json
```

- `iat`: 著名発行日時（UNIX時間）をつける場合は、`--set-iat`を指定します。

```sh
veriseal sign \
  --privkey privkey.pem \
  --input envelope.template.json \
  --payload-file payload.json \
  --output envelope.signed.json \
  --set-iat
```


### verify

- 署名検証を行います。payload を指定した場合は payload_hash も検証します。

```sh
veriseal verify \
  --pubkey pubkey.pem \
  --input envelope.signed.json

veriseal verify \
  --pubkey pubkey.pem \
  --input envelope.signed.json \
  --payload-file payload.json
```

### Timeseries

Timeseries は、Envelope の連続性（欠落・並び替え・分岐）を検証可能にするための補助コマンドです。

#### ts init

- 新しい timeseries セッションを開始します。

```sh
veriseal ts init \
  --kid demo-1 \
  --payload-encoding JCS \
  --output envelope.template.json
```

- 新しい `ts_session_id` を生成します
- `ts_seq = 0` を設定します
- `ts_prev` は設定されません
- 署名前の Envelope テンプレートを出力します

#### ts next

- 直前の署名済み Envelope を元に、次の Envelope テンプレートを生成します。

```sh
veriseal ts next \
  --prev envelope.prev.signed.json \
  --output envelope.template.json
```

- `ts_session_id` は前の Envelope から継承されます
- `ts_seq = prev.ts_seq + 1`
- `ts_prev` は、直前の unsigned Envelope に対するHA-256 ハッシュ（Base64）として計算されます
- 署名前の Envelope テンプレートを出力します

#### ts check

- 2つの Envelope 間の連続性を確認します。
- 主に ingest 時の即時チェック用途を想定しています。

```sh
veriseal ts check \
  --prev prev.signed.json \
  --current current.signed.json
```

#### ts audit

- 複数の Envelope を入力として、連続性のみを検証します。
- 署名検証や payload 検証は行いません。

```sh
veriseal ts audit \
  --input envelopes.jsonl
```

検証内容：
- `ts_session_id` が一貫していること
- `ts_seq` が 0 から単調増加していること
- `ts_prev` が直前の Envelope と一致していること

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

