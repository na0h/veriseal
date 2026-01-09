
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

```
# private (PKCS#8 PEM)
openssl genpkey -algorithm ED25519 -out .local/keys/ed25519.priv.pem

# public (SPKI PEM)
openssl pkey -in .local/keys/ed25519.priv.pem -pubout -out .local/keys/ed25519.pub.pem
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
$ go run ./cmd/veriseal sign --privkey .local/keys/ed25519.priv.pem --input .local/input/envelope.json --payload-file .local/input/payload.json --output .local/out/envelope.signed.json

```

### raw

```
$ go run ./cmd/veriseal sign --privkey .local/keys/ed25519.priv.pem --input .local/input/envelope.raw.json --payload-file .local/input/payload.bin --output .local/out/envelope.raw.signed.json
```

## verify

### json

```
$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.pem --input .local/out/envelope.signed.json

$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.pem --input .local/out/envelope.signed.json --payload-file .local/input/payload.json
```

### raw

```
$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.pem --input .local/out/envelope.raw.signed.json

$ go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.pem --input .local/out/envelope.raw.signed.json --payload-file .local/input/payload.bin
```
