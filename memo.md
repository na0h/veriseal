
# コマンドメモ


```
$ mkdir -p .local/keys
$ go run ./tools/genkey keygen --out .local/keys
```

```
$ mkdir -p .local/input
$ mkdir -p .local/out
$ echo hello world > .local/input/payload.bin
```

## unit test

```
$ go test ./...
```

## canonical

### json

```
$ go run ./cmd/veriseal canon --input .local/input/payload.json --output .local/out/payload.canon.json
```

## sign

### json

```
$ go run ./cmd/veriseal sign --privkey .local/keys/ed25519.priv.b64 --input .local/input/envelope.json --payload-file .local/input/payload.json --payload-encoding JCS --output .local/out/envelope.signed.json
```

### raw

```
$ go run ./cmd/veriseal sign --privkey .local/keys/ed25519.priv.b64 --input .local/out/envelope.json --payload-file .local/input/payload.bin  --payload-encoding raw --output .local/out/envelope.signed.json
```

## verify

### json

```
$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.b64 --input .local/out/envelope.signed.json

$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.b64 --input .local/out/envelope.signed.json --payload-file .local/input/payload.json
```

### raw

```
$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.b64 --input .local/out/envelope.signed.json --payload-file .local/input/payload.bin
```
