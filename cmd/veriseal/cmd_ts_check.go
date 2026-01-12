package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/na0h/veriseal/core"
)

func runTSCheck(args []string) error {
	fs := flag.NewFlagSet("ts check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	prevPath := fs.String("prev", "", "previous signed envelope JSON file")
	currPath := fs.String("curr", "", "current signed envelope JSON file")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printTSCheckUsage(os.Stdout)
			return nil
		}
		printTSCheckUsage(os.Stderr)
		return err
	}

	if *prevPath == "" || *currPath == "" {
		printTSCheckUsage(os.Stderr)
		return errors.New("missing --prev or --curr")
	}

	prevBytes, err := readInput(*prevPath)
	if err != nil {
		return err
	}
	currBytes, err := readInput(*currPath)
	if err != nil {
		return err
	}

	var prev core.Envelope
	if err := json.Unmarshal(prevBytes, &prev); err != nil {
		return err
	}
	var curr core.Envelope
	if err := json.Unmarshal(currBytes, &curr); err != nil {
		return err
	}

	if err := core.CheckTimeseriesLinkV1(prev, curr); err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, "OK")
	return nil
}
