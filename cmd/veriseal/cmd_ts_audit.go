package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/na0h/veriseal/core"
)

func runTSAudit(args []string) error {
	fs := flag.NewFlagSet("ts audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inPath := fs.String("input", "", "input JSONL file (signed envelopes)")
	strictStart := fs.Bool("strict-start", false, "require ts_seq=0 and empty ts_prev on the first line")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printTSAuditUsage(os.Stdout)
			return nil
		}
		printTSAuditUsage(os.Stderr)
		return err
	}
	if *inPath == "" {
		printTSAuditUsage(os.Stderr)
		return errors.New("missing --input")
	}

	var r io.Reader
	if *inPath == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(*inPath)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)

	var envs []core.Envelope
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e core.Envelope
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		envs = append(envs, e)
	}
	if err := sc.Err(); err != nil {
		return err
	}

	if err := core.AuditTimeseriesV1(envs, *strictStart); err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, "OK")
	return nil
}
