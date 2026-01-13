package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/na0h/veriseal/core"
)

type tsNextResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func runTSNext(args []string) error {
	fs := flag.NewFlagSet("ts next", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inPath := fs.String("prev", "", "input signed envelope JSON file (previous)")
	outPath := fs.String("output", "", "output file path (default: stdout)")
	jsonOut := fs.Bool("json", false, "output result as JSON (for CI / automation); when set, writes envelope JSON to --output (required)")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printTSNextUsage(os.Stdout)
			return nil
		}
		printTSNextUsage(os.Stderr)
		return err
	}

	if *inPath == "" {
		printTSNextUsage(os.Stderr)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(tsNextResult{OK: false, Error: "missing --prev"})
		}
		return errors.New("missing --prev")
	}
	if *jsonOut && *outPath == "" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(tsNextResult{OK: false, Error: "missing --output (required when --json is set)"})
		return errors.New("missing --output")
	}

	b, err := readInput(*inPath)
	if err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(tsNextResult{OK: false, Error: err.Error()})
		}
		return err
	}

	var prev core.Envelope
	if err := json.Unmarshal(b, &prev); err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(tsNextResult{OK: false, Error: err.Error()})
		}
		return err
	}

	next, err := core.NextTimeseriesEnvelopeTemplateV1(prev)
	if err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(tsNextResult{OK: false, Error: err.Error()})
		}
		return err
	}

	out, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(tsNextResult{OK: false, Error: err.Error()})
		}
		return err
	}
	out = append(out, '\n')

	if *jsonOut {
		if err := writeOutput(*outPath, out); err != nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(tsNextResult{OK: false, Error: err.Error()})
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(tsNextResult{OK: true})
		return nil
	}

	if err := writeOutput(*outPath, out); err != nil {
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(tsNextResult{OK: false, Error: err.Error()})
		}
		return err
	}
	return nil
}
