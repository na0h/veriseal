package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/na0h/veriseal/canonical"
)

func SignEd25519(env Envelope, priv ed25519.PrivateKey) (Envelope, error) {
	if env.V == 0 {
		env.V = 0
	}
	if env.Alg == "" {
		env.Alg = "Ed25519"
	}
	if env.Alg != "Ed25519" {
		return Envelope{}, errors.New("unsupported alg: " + env.Alg)
	}

	unsigned := env
	unsigned.Sig = ""

	b, err := json.Marshal(unsigned)
	if err != nil {
		return Envelope{}, err
	}

	msg, err := canonical.Canonicalize(b)
	if err != nil {
		return Envelope{}, err
	}

	sig := ed25519.Sign(priv, msg)
	env.Sig = base64.StdEncoding.EncodeToString(sig)
	return env, nil
}
