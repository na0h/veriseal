package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/na0h/veriseal/canonical"
	"github.com/na0h/veriseal/core"
	"github.com/na0h/veriseal/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: veriseal <canon|sign|verify> [options]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "canon":
		runCanon(os.Args[2:])
	case "sign":
		runSign(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(1)
	}
}

func runCanon(args []string) {
	fs := flag.NewFlagSet("canon", flag.ExitOnError)
	inPath := fs.String("input", "", "input file path (default: stdin)")
	outPath := fs.String("output", "", "output file path (default: stdout)")
	_ = fs.Parse(args)

	input, err := readInput(*inPath)
	if err != nil {
		fatal(err)
	}

	out, err := canonical.Canonicalize(input)
	if err != nil {
		fatal(err)
	}

	if err := writeOutput(*outPath, out); err != nil {
		fatal(err)
	}
}

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	privPath := fs.String("privkey", "", "path to ed25519 private key (base64 or raw 64 bytes)")
	inPath := fs.String("input", "", "input file path (default: stdin)")
	outPath := fs.String("output", "", "output file path (default: stdout)")

	payloadFile := fs.String("payload-file", "", "payload file path (required for v=1)")
	payloadType := fs.String("payload-type", "application/octet-stream", "payload type (v=1)")

	_ = fs.Parse(args)

	if *privPath == "" {
		fatal(fmt.Errorf("missing --privkey"))
	}

	priv, err := crypto.LoadEd25519PrivateKey(*privPath)
	if err != nil {
		fatal(err)
	}

	input, err := readInput(*inPath)
	if err != nil {
		fatal(err)
	}

		// v1 path (payload-hash signing)
		if *payloadFile == "" {
			fatal(fmt.Errorf("v=1 requires --payload-file"))
		}
		payloadBytes, err := os.ReadFile(*payloadFile)
		if err != nil {
			fatal(err)
		}

		var env1 core.Envelope
		if err := json.Unmarshal(input, &env1); err != nil {
			fatal(err)
		}

		// enforce v1 and allow payload_type from flag
		env1.V = 1
		if env1.PayloadType == "" {
			env1.PayloadType = *payloadType
		}
		signed, err := core.SignEd25519V1(env1, payloadBytes, priv)
		if err != nil {
			fatal(err)
		}

		out, err := json.Marshal(signed)
		if err != nil {
			fatal(err)
		}
		if err := writeOutput(*outPath, out); err != nil {
			fatal(err)
		}
}


func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pubkey", "", "path to ed25519 public key (base64 or raw 32 bytes)")
	inPath := fs.String("input", "", "input file path (default: stdin)")

	payloadFile := fs.String("payload-file", "", "payload file path (optional; if set, hash is verified for v=1)")

	_ = fs.Parse(args)

	if *pubPath == "" {
		fatal(fmt.Errorf("missing --pubkey"))
	}

	pub, err := crypto.LoadEd25519PublicKey(*pubPath)
	if err != nil {
		fatal(err)
	}

	input, err := readInput(*inPath)
	if err != nil {
		fatal(err)
	}

		var env1 core.Envelope
		if err := json.Unmarshal(input, &env1); err != nil {
			fatal(err)
		}

		var payloadBytes []byte
		if *payloadFile != "" {
			b, err := os.ReadFile(*payloadFile)
			if err != nil {
				fatal(err)
			}
			payloadBytes = b
		}

		if err := core.VerifyEd25519V1(env1, pub, payloadBytes); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stdout, "OK")
}


func readInput(path string) ([]byte, error) {
	if path == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, b []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
