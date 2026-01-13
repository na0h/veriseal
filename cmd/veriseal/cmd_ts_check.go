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

type tsCheckResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func runTSCheck(args []string) error {
	fs := flag.NewFlagSet("ts check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	prevPath := fs.String("prev", "", "previous signed envelope JSON file")
	currPath := fs.String("curr", "", "current signed envelope JSON file")
	jsonOut := fs.Bool("json", false, "output result as JSON")

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

	err = core.CheckTimeseriesLinkV1(prev, curr)

	if *jsonOut {
		res := tsCheckResult{OK: err == nil}
		if err != nil {
			res.Error = err.Error()
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(res)
		return err
	}

	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "OK")
	return nil
}
