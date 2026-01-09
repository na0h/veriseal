package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/na0h/veriseal/canonical"
	"github.com/na0h/veriseal/cmd/veriseal/internal"
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
	privPath := fs.String("privkey", "", "path to ed25519 private key")
	inPath := fs.String("input", "", "input file path")
	outPath := fs.String("output", "", "output file path")

	payloadFile := fs.String("payload-file", "", "payload file path")

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

	if *payloadFile == "" {
		fatal(fmt.Errorf("requires --payload-file"))
	}
	payloadBytes, err := os.ReadFile(*payloadFile)
	if err != nil {
		fatal(err)
	}

	var envelope core.Envelope
	if err := json.Unmarshal(input, &envelope); err != nil {
		fatal(err)
	}

	signed, err := core.SignEd25519(envelope, payloadBytes, priv)
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
	pubPath := fs.String("pubkey", "", "path to ed25519 public key")
	inPath := fs.String("input", "", "input signed file path")

	payloadFile := fs.String("payload-file", "", "payload file path")

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

	var envelope core.Envelope
	if err := json.Unmarshal(input, &envelope); err != nil {
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

	var verifiedPayloadHash *bool
	if payloadBytes != nil {
		if err := core.VerifyPayloadHash(envelope, payloadBytes); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL:", err)
			verifiedPayloadHash = internal.BoolPtr(false)
		} else {
			verifiedPayloadHash = internal.BoolPtr(true)
		}
	}

	verifiedEd25519 := false
	if err := core.VerifyEd25519(envelope, pub); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
	} else {
		verifiedEd25519 = true
	}

	if verifiedEd25519 {
		fmt.Fprintln(os.Stdout, "Verify signed: OK")
	} else {
		fmt.Fprintln(os.Stdout, "Verify signed: FAILED")
	}

	switch {
	case verifiedPayloadHash == nil:
		fmt.Fprintln(os.Stdout, "Verify payload hash: UNKNOWN")
	case *verifiedPayloadHash:
		fmt.Fprintln(os.Stdout, "Verify payload hash: OK")
	default:
		fmt.Fprintln(os.Stdout, "Verify payload hash: FAILED")
	}
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
