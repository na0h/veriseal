package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/na0h/veriseal/canonical"
	"github.com/na0h/veriseal/core"
	"github.com/na0h/veriseal/crypto"
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
		{name: "envelope", run: runEnvelope, help: "Print an Envelope v1 JSON template."},
		{name: "sign", run: runSign, help: "Sign an envelope (Sig empty) with Ed25519 using a payload file."},
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

// Envelope template
func runEnvelope(args []string) error {
	fs := flag.NewFlagSet("envelope", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	kid := fs.String("kid", "", "key id (optional)")
	payloadEncoding := fs.String("payload-encoding", core.V1PayloadEncodingJCS, "payload encoding: JCS or raw")
	outPath := fs.String("output", "", "output file path (default: stdout)")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printEnvelopeUsage(os.Stdout)
			return nil
		}
		printEnvelopeUsage(os.Stderr)
		return err
	}

	enc := *payloadEncoding
	if enc != core.V1PayloadEncodingJCS && enc != core.V1PayloadEncodingRaw {
		printEnvelopeUsage(os.Stderr)
		return fmt.Errorf("invalid --payload-encoding: %s", enc)
	}

	env := core.Envelope{
		V:               core.Version1,
		Alg:             core.V1AlgEd25519,
		Kid:             *kid,
		PayloadEncoding: enc,
		PayloadHashAlg:  core.V1PayloadHashAlgSHA256,
		PayloadHash:     "",
		Sig:             "",
	}

	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return writeOutput(*outPath, out)
}

func printEnvelopeUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: veriseal envelope [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "options:")
	fmt.Fprintln(w, "  --kid              key id (optional)")
	fmt.Fprintln(w, "  --payload-encoding payload encoding: JCS or raw (default: JCS)")
	fmt.Fprintln(w, "  --output           output file path (default: stdout)")
}

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

func printCanonUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: veriseal canon [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "options:")
	fmt.Fprintln(w, "  -input   input file path (default: stdin)")
	fmt.Fprintln(w, "  -output  output file path (default: stdout)")
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	privPath := fs.String("privkey", "", "path to ed25519 private key")
	inPath := fs.String("input", "", "input envelope JSON file path")
	outPath := fs.String("output", "", "output file path (default: stdout)")
	payloadFile := fs.String("payload-file", "", "payload file path")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printSignUsage(os.Stdout)
			return nil
		}
		printSignUsage(os.Stderr)
		return err
	}

	if *privPath == "" {
		printSignUsage(os.Stderr)
		return fmt.Errorf("missing --privkey")
	}
	if *inPath == "" {
		printSignUsage(os.Stderr)
		return fmt.Errorf("missing --input")
	}
	if *payloadFile == "" {
		printSignUsage(os.Stderr)
		return fmt.Errorf("missing --payload-file")
	}

	priv, err := crypto.LoadEd25519PrivateKey(*privPath)
	if err != nil {
		return err
	}

	input, err := readInput(*inPath)
	if err != nil {
		return err
	}

	payloadBytes, err := os.ReadFile(*payloadFile)
	if err != nil {
		return err
	}

	var envelope core.Envelope
	if err := json.Unmarshal(input, &envelope); err != nil {
		return err
	}

	signed, err := core.SignEd25519(envelope, payloadBytes, priv)
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return writeOutput(*outPath, out)
}

func printSignUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: veriseal sign --privkey <path> --input <envelope.json> --payload-file <payload> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "required:")
	fmt.Fprintln(w, "  --privkey       path to ed25519 private key (PKCS#8 PEM)")
	fmt.Fprintln(w, "  --input         envelope JSON file (Sig should be empty)")
	fmt.Fprintln(w, "  --payload-file  payload file path")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "options:")
	fmt.Fprintln(w, "  --output        output file path (default: stdout)")
}

type verifyResult struct {
	SignatureOK    bool   `json:"signature_ok"`
	PayloadHashOK  *bool  `json:"payload_hash_ok,omitempty"`
	SignatureError string `json:"signature_error,omitempty"`
	PayloadError   string `json:"payload_error,omitempty"`
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	pubPath := fs.String("pubkey", "", "path to ed25519 public key")
	inPath := fs.String("input", "", "input signed envelope JSON file path")
	payloadFile := fs.String("payload-file", "", "payload file path (optional)")
	jsonOut := fs.Bool("json", false, "print result as JSON")

	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printVerifyUsage(os.Stdout)
			return nil
		}
		printVerifyUsage(os.Stderr)
		return err
	}

	if *pubPath == "" {
		printVerifyUsage(os.Stderr)
		return fmt.Errorf("missing --pubkey")
	}
	if *inPath == "" {
		printVerifyUsage(os.Stderr)
		return fmt.Errorf("missing --input")
	}

	pub, err := crypto.LoadEd25519PublicKey(*pubPath)
	if err != nil {
		return err
	}

	input, err := readInput(*inPath)
	if err != nil {
		return err
	}

	var envelope core.Envelope
	if err := json.Unmarshal(input, &envelope); err != nil {
		return err
	}

	res := verifyResult{}

	// Optional payload hash verification
	if *payloadFile != "" {
		payloadBytes, err := os.ReadFile(*payloadFile)
		if err != nil {
			return err
		}
		if err := core.VerifyPayloadHash(envelope, payloadBytes); err != nil {
			f := false
			res.PayloadHashOK = &f
			res.PayloadError = err.Error()
		} else {
			t := true
			res.PayloadHashOK = &t
		}
	}

	// Signature verification
	if err := core.VerifyEd25519(envelope, pub); err != nil {
		res.SignatureOK = false
		res.SignatureError = err.Error()
	} else {
		res.SignatureOK = true
	}

	if *jsonOut {
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(b))
		return nil
	}

	// Human-readable output
	if res.SignatureOK {
		fmt.Fprintln(os.Stdout, "Verify signed: OK")
	} else {
		fmt.Fprintln(os.Stdout, "Verify signed: FAILED")
		if res.SignatureError != "" {
			fmt.Fprintln(os.Stdout, "  reason:", res.SignatureError)
		}
	}

	switch {
	case res.PayloadHashOK == nil:
		fmt.Fprintln(os.Stdout, "Verify payload hash: UNKNOWN")
	case *res.PayloadHashOK:
		fmt.Fprintln(os.Stdout, "Verify payload hash: OK")
	default:
		fmt.Fprintln(os.Stdout, "Verify payload hash: FAILED")
		if res.PayloadError != "" {
			fmt.Fprintln(os.Stdout, "  reason:", res.PayloadError)
		}
	}

	return nil
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

func parseFlags(fs *flag.FlagSet, args []string) error {
	// flag package prints to fs.Output; we discard and handle ourselves.
	if err := fs.Parse(args); err != nil {
		return err
	}
	return nil
}

func readInput(path string) ([]byte, error) {
	if path == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, b []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0644)
}
