package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/na0h/veriseal/core"
)

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	kid := fs.String("kid", "", "key id")
	payloadEncoding := fs.String("payload-encoding", core.V1PayloadEncodingJCS, "payload encoding: jcs or raw")
	outPath := fs.String("output", "", "output file path (default: stdout)")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printInitUsage(os.Stdout)
			return nil
		}
		printInitUsage(os.Stderr)
		return err
	}

	env, err := core.NewEnvelopeTemplateV1(*kid, *payloadEncoding)
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return writeOutput(*outPath, out)
}
