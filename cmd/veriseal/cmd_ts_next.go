package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/na0h/veriseal/core"
)

func runTSNext(args []string) error {
	fs := flag.NewFlagSet("ts next", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inPath := fs.String("prev", "", "input signed envelope JSON file (previous)")
	outPath := fs.String("output", "", "output file path (default: stdout)")

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
		return errors.New("missing --input")
	}

	b, err := readInput(*inPath)
	if err != nil {
		return err
	}

	var prev core.Envelope
	if err := json.Unmarshal(b, &prev); err != nil {
		return err
	}

	next, err := core.NextTimeseriesEnvelopeTemplateV1(prev)
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return writeOutput(*outPath, out)
}
