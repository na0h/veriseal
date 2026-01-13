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
	"strings"

	"github.com/na0h/veriseal/core"
)

type tsAuditResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Index *int   `json:"index,omitempty"`
}

func parseAuditIndex(msg string) *int {
	const prefix = "index "
	if !strings.HasPrefix(msg, prefix) {
		return nil
	}
	var n int
	if _, err := fmt.Sscanf(msg, "index %d:", &n); err == nil {
		return &n
	}
	return nil
}

func runTSAudit(args []string) error {
	fs := flag.NewFlagSet("ts audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	inPath := fs.String("input", "", "input JSONL file (signed envelopes)")
	strictStart := fs.Bool("strict-start", false, "require ts_seq=0 and empty ts_prev on the first line")
	jsonOut := fs.Bool("json", false, "output result as JSON")

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
		defer f.Close() //nolint:errcheck
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

	err := core.AuditTimeseriesV1(envs, *strictStart)

	if *jsonOut {
		res := tsAuditResult{OK: err == nil}
		if err != nil {
			res.Error = err.Error()
			res.Index = parseAuditIndex(res.Error)
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
