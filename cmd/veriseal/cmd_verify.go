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

type verifyResult struct {
	SignatureOK    bool   `json:"signature_ok"`
	PayloadHashOK  *bool  `json:"payload_hash_ok,omitempty"`
	SignatureError string `json:"signature_error,omitempty"`
	PayloadError   string `json:"payload_error,omitempty"`
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	pubPath := fs.String("pubkey", "", "path to ed25519 public key")
	inPath := fs.String("input", "", "input signed envelope JSON file path")
	payloadFile := fs.String("payload-file", "", "payload file path (optional)")
	jsonOut := fs.Bool("json", false, "print result as JSON")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printVerifyUsage(os.Stdout)
			return nil
		}
		printVerifyUsage(os.Stderr)
		return err
	}

	if *pubPath == "" {
		printVerifyUsage(os.Stderr)
		return fmt.Errorf("missing --pubkey")
	}
	if *inPath == "" {
		printVerifyUsage(os.Stderr)
		return fmt.Errorf("missing --input")
	}

	pub, err := crypto.LoadEd25519PublicKey(*pubPath)
	if err != nil {
		return err
	}

	input, err := readInput(*inPath)
	if err != nil {
		return err
	}

	var envelope core.Envelope
	if err := json.Unmarshal(input, &envelope); err != nil {
		return err
	}

	res := verifyResult{}

	// Optional payload hash verification
	if *payloadFile != "" {
		payloadBytes, err := os.ReadFile(*payloadFile)
		if err != nil {
			return err
		}
		if err := core.VerifyPayloadHash(envelope, payloadBytes); err != nil {
			f := false
			res.PayloadHashOK = &f
			res.PayloadError = err.Error()
		} else {
			t := true
			res.PayloadHashOK = &t
		}
	}

	// Signature verification
	if err := core.VerifyEd25519(envelope, pub); err != nil {
		res.SignatureOK = false
		res.SignatureError = err.Error()
	} else {
		res.SignatureOK = true
	}

	if *jsonOut {
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(b))
		return nil
	}

	// Human-readable output
	if res.SignatureOK {
		fmt.Fprintln(os.Stdout, "Verify signed: OK")
	} else {
		fmt.Fprintln(os.Stdout, "Verify signed: FAILED")
		if res.SignatureError != "" {
			fmt.Fprintln(os.Stdout, "  reason:", res.SignatureError)
		}
	}

	switch {
	case res.PayloadHashOK == nil:
		fmt.Fprintln(os.Stdout, "Verify payload hash: UNKNOWN")
	case *res.PayloadHashOK:
		fmt.Fprintln(os.Stdout, "Verify payload hash: OK")
	default:
		fmt.Fprintln(os.Stdout, "Verify payload hash: FAILED")
		if res.PayloadError != "" {
			fmt.Fprintln(os.Stdout, "  reason:", res.PayloadError)
		}
	}

	return nil
}
