package testutil

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var Update = flag.Bool("update", false, "update golden files") // go test ./... -update

func DiffOrUpdate(t *testing.T, path string, got []byte) {
	t.Helper()

	if *Update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	// “改行だけ”で落ちるのが鬱陶しいなら TrimSpace。完全バイト一致にしたいなら外す。
	want = bytes.TrimSpace(want)
	got = bytes.TrimSpace(got)

	if !bytes.Equal(want, got) {
		t.Fatalf("golden mismatch: %s\n---want---\n%s\n---got---\n%s\n", path, want, got)
	}
}
