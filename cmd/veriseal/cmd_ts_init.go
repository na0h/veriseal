package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/na0h/veriseal/core"
)

func runTSInit(args []string) error {
	fs := flag.NewFlagSet("ts init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	kid := fs.String("kid", "", "key id")
	payloadEncoding := fs.String("payload-encoding", core.V1PayloadEncodingJCS, "payload encoding: JCS or raw")
	outPath := fs.String("output", "", "output file path (default: stdout)")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printTSInitUsage(os.Stdout)
			return nil
		}
		printTSInitUsage(os.Stderr)
		return err
	}

	env, err := core.NewTimeseriesEnvelopeTemplateV1(*kid, *payloadEncoding)
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
