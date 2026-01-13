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

type signResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	privPath := fs.String("privkey", "", "path to ed25519 private key")
	inPath := fs.String("input", "", "input envelope JSON file path")
	outPath := fs.String("output", "", "output file path (default: stdout)")
	payloadFile := fs.String("payload-file", "", "payload file path")
	setIat := fs.Bool("set-iat", false, "set iat (epoch seconds) right before signing")
	jsonOut := fs.Bool("json", false, "output result as JSON (for CI / automation); when set, writes signed envelope JSON to --output (required)")

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
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: "missing --privkey"})
		}
		return fmt.Errorf("missing --privkey")
	}
	if *inPath == "" {
		printSignUsage(os.Stderr)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: "missing --input"})
		}
		return fmt.Errorf("missing --input")
	}
	if *payloadFile == "" {
		printSignUsage(os.Stderr)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: "missing --payload-file"})
		}
		return fmt.Errorf("missing --payload-file")
	}
	if *jsonOut && *outPath == "" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(signResult{OK: false, Error: "missing --output (required when --json is set)"})
		return fmt.Errorf("missing --output")
	}

	priv, err := crypto.LoadEd25519PrivateKey(*privPath)
	if err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: err.Error()})
		}
		return err
	}

	input, err := readInput(*inPath)
	if err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: err.Error()})
		}
		return err
	}

	payloadBytes, err := os.ReadFile(*payloadFile)
	if err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: err.Error()})
		}
		return err
	}

	var envelope core.Envelope
	if err := json.Unmarshal(input, &envelope); err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: err.Error()})
		}
		return err
	}

	signed, err := core.SignEd25519(envelope, payloadBytes, priv, *setIat)
	if err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: err.Error()})
		}
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
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: err.Error()})
		}
		return err
	}
	out = append(out, '\n')

	if *jsonOut {
		if err := writeOutput(*outPath, out); err != nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(signResult{OK: false, Error: err.Error()})
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(signResult{OK: true})
		return nil
	}

	return writeOutput(*outPath, out)
}
