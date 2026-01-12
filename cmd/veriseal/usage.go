package main

import (
	"fmt"
	"io"
	"os"
)

func printUsage(w io.Writer, cmds []command) {
	fmt.Fprintln(w, "usage: veriseal <command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	for _, c := range cmds {
		fmt.Fprintf(w, "  %-8s %s\n", c.name, c.help)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "run 'veriseal <command> -h' for command-specific options")
}

func runVersion(args []string) error {
	fmt.Fprintln(os.Stdout, version)
	return nil
}

func printInitUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: veriseal init [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "options:")
	fmt.Fprintln(w, "  --kid              key id")
	fmt.Fprintln(w, "  --payload-encoding payload encoding: JCS or raw (default: JCS)")
	fmt.Fprintln(w, "  --output           output file path (default: stdout)")
}

func printCanonUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: veriseal canon [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "options:")
	fmt.Fprintln(w, "  -input   input file path (default: stdin)")
	fmt.Fprintln(w, "  -output  output file path (default: stdout)")
}

func printSignUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: veriseal sign --privkey <path> --input <envelope.json> --payload-file <payload> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "required:")
	fmt.Fprintln(w, "  --privkey       path to ed25519 private key (PKCS#8 PEM)")
	fmt.Fprintln(w, "  --input         envelope template JSON file")
	fmt.Fprintln(w, "  --payload-file  payload file path")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "options:")
	fmt.Fprintln(w, "  --set-iat       set iat (epoch seconds) right before signing")
	fmt.Fprintln(w, "  --output        output file path (default: stdout)")
}

func printVerifyUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: veriseal verify --pubkey <path> --input <signed.json> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "required:")
	fmt.Fprintln(w, "  --pubkey        path to ed25519 public key (SPKI PEM)")
	fmt.Fprintln(w, "  --input         signed envelope JSON file")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "options:")
	fmt.Fprintln(w, "  --payload-file  payload file path (optional; enables payload_hash verification)")
	fmt.Fprintln(w, "  --json          print machine-readable JSON result")
}

func printTSUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: veriseal ts <subcommand> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "subcommands:")
	fmt.Fprintln(w, "  init   Start a new timeseries session and print an Envelope v1 JSON template.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "run 'veriseal ts <subcommand> -h' for subcommand-specific options")
}

func printTSInitUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: veriseal ts init [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "options:")
	fmt.Fprintln(w, "  --kid              key id")
	fmt.Fprintln(w, "  --payload-encoding payload encoding: JCS or raw (default: JCS)")
	fmt.Fprintln(w, "  --output           output file path (default: stdout)")
}
