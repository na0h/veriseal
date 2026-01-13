package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/na0h/veriseal/core"
)

type tsInitResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func runTSInit(args []string) error {
	fs := flag.NewFlagSet("ts init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	kid := fs.String("kid", "", "key id")
	payloadEncoding := fs.String("payload-encoding", core.V1PayloadEncodingJCS, "payload encoding: jcs or raw")
	outPath := fs.String("output", "", "output file path (default: stdout)")
	jsonOut := fs.Bool("json", false, "output result as JSON (for CI / automation); when set, writes envelope to --output")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printTSInitUsage(os.Stdout)
			return nil
		}
		printTSInitUsage(os.Stderr)
		return err
	}

	if *kid == "" {
		if *jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(tsInitResult{OK: false, Error: "missing --kid"})
		}
		return errors.New("missing --kid")
	}
	if *jsonOut && *outPath == "" {
		_ = json.NewEncoder(os.Stdout).Encode(tsInitResult{OK: false, Error: "missing --output (required when --json is set)"})
		return errors.New("missing --output")
	}

	env, err := core.NewTimeseriesEnvelopeTemplateV1(*kid, *payloadEncoding)
	if err != nil {
		if *jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(tsInitResult{OK: false, Error: err.Error()})
		}
		return err
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		if *jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(tsInitResult{OK: false, Error: err.Error()})
		}
		return err
	}
	out = append(out, '\n')

	if *jsonOut {
		if err := writeOutput(*outPath, out); err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(tsInitResult{OK: false, Error: err.Error()})
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(tsInitResult{OK: true})
		return nil
	}

	return writeOutput(*outPath, out)
}
