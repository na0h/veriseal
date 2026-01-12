package main

import (
	"errors"
	"flag"
	"io"
	"os"

	"github.com/na0h/veriseal/canonical"
)

func runCanon(args []string) error {
	fs := flag.NewFlagSet("canon", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inPath := fs.String("input", "", "input file path (default: stdin)")
	outPath := fs.String("output", "", "output file path (default: stdout)")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printCanonUsage(os.Stdout)
			return nil
		}
		printCanonUsage(os.Stderr)
		return err
	}

	input, err := readInput(*inPath)
	if err != nil {
		return err
	}

	out, err := canonical.Canonicalize(input)
	if err != nil {
		return err
	}
	if *outPath == "" {
		out = append(out, '\n')
	}

	return writeOutput(*outPath, out)
}
