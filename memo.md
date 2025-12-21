
# コマンドメモ
```
$ go run .\tools\genkey keygen --out .local/keys
```

```
$ go run ./cmd/veriseal sign --privkey .local/keys/ed25519.priv.b64 --input .local/input/envelope.json --payload-file .local/input/payload.json --payload-encoding JCS --output .local/out/envelope.signed.json

$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.b64 --input .local/out/envelope.signed.json

$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.b64 --input .local/out/envelope.signed.json --payload-file .local/input/payload.json
```
```
$ echo hello world > .local/input/payload.bin

$ go run ./cmd/veriseal sign --privkey .local/keys/ed25519.priv.b64 --input .local/out/envelope.signed.json --payload-file .local/input/payload.bin  --payload-encoding raw --output .local/out/envelope.signed.json

$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.b64 --input .local/out/envelope.signed.json --payload-file .local/input/payload.bin
```