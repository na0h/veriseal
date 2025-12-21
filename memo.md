
echo hello world > .local/out/payload.bin

go run ./cmd/veriseal canon --input .local/input/input.json --output .local/out/out.canon.json
go run ./cmd/veriseal sign --privkey .local/keys/ed25519.priv.b64 --input .local/input/input.json --payload-file .local/out/payload.bin --output .local/out/signed.json
go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.b64 --input .local/out/signed.json
go run ./cmd/veriseal verify --pubkey .local/keys/ed25519.pub.b64 --input .local/out/signed.json --payload-file .local/out/payload.bin


go test ./...