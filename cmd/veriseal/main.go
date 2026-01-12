package main

import (
	"fmt"
	"os"
)

const (
	exitOK   = 0
	exitFail = 1
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

type command struct {
	name string
	run  func(args []string) error
	help string
}

func main() {
	cmds := []command{
		{name: "canon", run: runCanon, help: "Canonicalize JSON input using JCS."},
		{name: "init", run: runInit, help: "Print an Envelope v1 JSON template."},
		{name: "ts", run: runTS, help: "Timeseries helpers (init/next/check/audit)."},
		{name: "sign", run: runSign, help: "Sign an envelope template with Ed25519 using a payload file."},
		{name: "verify", run: runVerify, help: "Verify Ed25519 signature and optionally verify payload_hash using a payload file."},
		{name: "version", run: runVersion, help: "Print veriseal version."},
	}

	args := os.Args[1:]
	if len(args) == 0 {
		printUsage(os.Stderr, cmds)
		os.Exit(exitFail)
	}
	if isHelpArg(args[0]) {
		printUsage(os.Stdout, cmds)
		os.Exit(exitOK)
	}

	name := args[0]
	if name == "help" {
		printUsage(os.Stdout, cmds)
		os.Exit(exitOK)
	}

	cmd := findCmd(cmds, name)
	if cmd == nil {
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", name)
		printUsage(os.Stderr, cmds)
		os.Exit(exitFail)
	}

	if err := cmd.run(args[1:]); err != nil {
		// Keep errors concise and stable.
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(exitFail)
	}
	os.Exit(exitOK)
}

func isHelpArg(s string) bool {
	switch s {
	case "-h", "--help", "help":
		return true
	default:
		return false
	}
}

func findCmd(cmds []command, name string) *command {
	for i := range cmds {
		if cmds[i].name == name {
			return &cmds[i]
		}
	}
	return nil
}

func runTS(args []string) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		printTSUsage(os.Stdout)
		return nil
	}

	sub := args[0]
	switch sub {
	case "init":
		return runTSInit(args[1:])
	default:
		printTSUsage(os.Stderr)
		return fmt.Errorf("unknown ts subcommand: %s", sub)
	}
}
