package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/na0h/veriseal/canonical"
)

func VerifyEd25519(env Envelope, pub ed25519.PublicKey) error {
	if env.Alg == "" {
		env.Alg = "Ed25519"
	}
	if env.Alg != "Ed25519" {
		return errors.New("unsupported alg: " + env.Alg)
	}
	if env.Sig == "" {
		return errors.New("missing sig")
	}

	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return errors.New("invalid sig (base64 decode failed)")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("invalid sig size")
	}

	unsigned := env
	unsigned.Sig = ""

	b, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}

	msg, err := canonical.Canonicalize(b)
	if err != nil {
		return err
	}

	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}
