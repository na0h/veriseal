package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = os.WriteFile("./.local/keys/ed25519.pub.b64", []byte(base64.StdEncoding.EncodeToString(pub)), 0644)
	_ = os.WriteFile("./.local/keys/ed25519.priv.b64", []byte(base64.StdEncoding.EncodeToString(priv)), 0600)
	fmt.Println("generated: ed25519.pub.b64, ed25519.priv.b64")
}
