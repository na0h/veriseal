package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/na0h/veriseal/core"
	"github.com/na0h/veriseal/crypto"
)

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	privPath := fs.String("privkey", "", "path to ed25519 private key")
	inPath := fs.String("input", "", "input envelope JSON file path")
	outPath := fs.String("output", "", "output file path (default: stdout)")
	payloadFile := fs.String("payload-file", "", "payload file path")
	setIat := fs.Bool("set-iat", false, "set iat (epoch seconds) right before signing")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printSignUsage(os.Stdout)
			return nil
		}
		printSignUsage(os.Stderr)
		return err
	}

	if *privPath == "" {
		printSignUsage(os.Stderr)
		return fmt.Errorf("missing --privkey")
	}
	if *inPath == "" {
		printSignUsage(os.Stderr)
		return fmt.Errorf("missing --input")
	}
	if *payloadFile == "" {
		printSignUsage(os.Stderr)
		return fmt.Errorf("missing --payload-file")
	}

	priv, err := crypto.LoadEd25519PrivateKey(*privPath)
	if err != nil {
		return err
	}

	input, err := readInput(*inPath)
	if err != nil {
		return err
	}

	payloadBytes, err := os.ReadFile(*payloadFile)
	if err != nil {
		return err
	}

	var envelope core.Envelope
	if err := json.Unmarshal(input, &envelope); err != nil {
		return err
	}

	signed, err := core.SignEd25519(envelope, payloadBytes, priv, *setIat)
	if err != nil {
		return err
	}

	if *setIat && envelope.Iat != nil {
		old := *envelope.Iat
		fmt.Fprintf(
			os.Stderr,
			"WARN: iat overwritten (old=%d, new=%d)\n",
			old,
			*signed.Iat,
		)
	}

	out, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return writeOutput(*outPath, out)
}
