package main

import (
	"flag"
	"io"
	"os"
)

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
