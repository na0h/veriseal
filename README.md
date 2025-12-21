# VeriSeal

VeriSeal は「検証可能なデータ（Verifiable Data）」を扱うための最小ツールキットです。

サーバーや EdgeGW を信頼せず、**最終的な正しさの判断をクライアントが行う**ことを前提にします。
クラウドは保存・転送の役割に留め、**信頼点にしません**。

このリポジトリはまず CLI を参照実装とし、署名・検証・正規化（JSON Canonicalization）の挙動を固定することを目的とします。

---

## 目的（Goals）

* データが改ざんされていないことを、第三者・後段システムが独立して検証できる状態を作る
* 以下を決定論的に行える最小実装を提供する

  * JSON の正規化（canonicalization）
  * 署名（Envelope への署名）
  * 検証（署名検証 + 任意で payload ハッシュ検証）
* 将来 API / Web / SDK を作っても挙動がブレない参照実装を作る

---

## やらないこと（Non-goals）

* サーバーを「正しさの源泉」にしない（サーバーは保存・配布のみ）
* core に I/O、CLI、ファイル操作、時刻取得を入れない
* 鍵管理・PKI・鍵配布基盤を作らない
* ブロックチェーンや台帳を扱わない
* 複数署名方式を同時にサポートしない（初期は Ed25519 のみ）

---

## 設計方針

### core と client を分離する

* **core**

  * 署名・検証・正規化の純粋ロジック
  * 同じ入力に対して同じ出力を返す
  * 環境依存コードを持たない
* **client**

  * CLI（参照実装）
  * 引数処理、stdin/stdout、鍵ファイル読み込み
  * 運用ポリシーの判断

CLI は便利ツールではなく、VeriSeal の挙動を定義する基準実装とします。

---

## リポジトリ構成（最小）

```
veriseal/
  cmd/
    veriseal/        # CLI（client）
  core/              # 署名・検証の中核
  canonical/         # JSON 正規化（RFC8785 JCS 相当）
  crypto/            # 暗号プリミティブ（Ed25519）
  testdata/
    vectors/         # テストベクタ（互換性の基準）
```

---

## データモデル（Envelope v1）

Envelope は **payload そのものを含めず**、payload を参照するためのハッシュと署名を持つ「証明書」です。

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

* `JCS`: payload は JSON。`payload_hash = SHA-256( JCS(payload) bytes )`
* `raw`: payload は binary bytes。`payload_hash = SHA-256(payload bytes)`

---

## 署名ルール（v1）

* `payload_hash = base64(SHA-256(payloadBytesNormalized))`

  * `payload_encoding=JCS` の場合: `payloadBytesNormalized = JCS(payload)`
  * `payload_encoding=raw` の場合: `payloadBytesNormalized = payloadBytes`
* `sig` は、`sig` フィールドを除いた Envelope を canonicalize した bytes に対する Ed25519 署名

---

## 検証ルール（v1）

検証は 2 軸で扱います。

* `signature_ok`: Envelope が署名通り改ざんされていない
* `payload_ok`: payload が与えられた場合に、`payload_hash` と一致する

  * payload が無い場合は `payload_ok = unknown`

---

## 通信モデル（推奨）

VeriSeal は payload の保存場所・配送方式を管理しません。Envelope は payload を指す「検証可能な参照」です。

### モードA: JSON-only（推奨）

センサー値など、JSON をそのまま送れるケースの第一選択です。

* `Content-Type: application/json`
* body: `{ envelope, payload }`
* Envelope: `payload_encoding = "JCS"`

例:

```json
{
  "envelope": {
    "v": 1,
    "alg": "Ed25519",
    "kid": "sensor-A",
    "payload_type": "application/json",
    "payload_encoding": "JCS",
    "payload_hash_alg": "SHA-256",
    "payload_hash": "BASE64...",
    "sig": "BASE64..."
  },
  "payload": {
    "sensor_id": "A-1",
    "ts": 1734796800,
    "temp": 23.4
  }
}
```

### モードB: multipart（binary 推奨）

CSV / msgpack / gzip / parquet 等の bytes を、そのまま送りたいケースの第一選択です。

* `Content-Type: multipart/form-data`
* parts:

  * `envelope`（`application/json`）
  * `payload`（任意の bytes。`text/csv` / `application/msgpack` / `application/octet-stream` など）
* Envelope: `payload_encoding = "raw"`

**hash 対象は payload part の body bytes のみ**（multipart の境界やヘッダ、ファイル名などは含めない）。
中継・保存は payload bytes を変更しないこと（改行変換・再圧縮・charset 変換などをしない）。

### モードC: JSON + base64（フォールバック）

どうしても 1 JSON で完結させたい場合の逃げ道です（サイズは増えます）。

* `Content-Type: application/json`
* body: `{ envelope, payload_b64 }`
* Envelope: `payload_encoding = "raw"`

---

## CLI

CLI は「payload bytes をどう解釈するか」を `payload_encoding` で固定し、同じ入力に対して同じ `payload_hash` と署名を生成します。

### canon

```sh
veriseal canon --input payload.json --output payload.canon.json
```

### sign

* JSON の場合（`payload_encoding=JCS`）: payload を JSON として読み取り、JCS bytes に正規化して hash
* binary の場合（`payload_encoding=raw`）: ファイル bytes をそのまま hash

```sh
veriseal sign \
  --privkey ./privkey \
  --input  envelope.json \
  --payload-file payload.json \
  --payload-encoding JCS \
  --output envelope.signed.json

veriseal sign \
  --privkey ./privkey \
  --input  envelope.json \
  --payload-file payload.bin \
  --payload-encoding raw \
  --output envelope.signed.json
```

### verify

payload を渡すと `payload_ok` まで検証します。

```sh
veriseal verify --pubkey ./pubkey --input envelope.signed.json
veriseal verify --pubkey ./pubkey --input envelope.signed.json --payload-file payload.bin
```

---

## 互換性ポリシー

* canonical（JCS 相当）の挙動はテストベクタで固定
* Envelope v1 のフィールドと検証規則は互換境界
* 破壊的変更はバージョンを上げる
