package canonical

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vector struct {
	Name string `json:"name"`
	In   string `json:"in"`
	Out  string `json:"out"`
}

func TestVectors(t *testing.T) {
	dir := filepath.Join("..", "testdata", "vectors")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "v0_canon_") || !strings.HasSuffix(name, ".json") {
				continue
		}
		found++

		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		var v vector
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		got, err := Canonicalize([]byte(v.In))
		if err != nil {
			t.Fatalf("%s (%s): %v", name, v.Name, err)
		}

		if string(got) != v.Out {
			t.Fatalf("%s (%s): mismatch\n got: %q\nwant: %q", name, v.Name, string(got), v.Out)
		}
	}

	if found == 0 {
		t.Fatalf("no canonical vectors found ... (expected files like v0_canon_*.json)")
	}
}
