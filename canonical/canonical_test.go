package canonical

import (
	"errors"
	"testing"
)

func TestCanonicalize_EmptyInputRejected(t *testing.T) {
	_, err := Canonicalize([]byte{})
	if err == nil {
		t.Fatalf("want ErrEmptyInput, got nil")
	}
	if !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("want ErrEmptyInput, got %v", err)
	}
}

func TestCanonicalize_EmptyObjectOK(t *testing.T) {
	out, err := Canonicalize([]byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != `{}` {
		t.Fatalf("want %q, got %q", `{}`, string(out))
	}
}

func TestCanonicalize_SortsKeys(t *testing.T) {
	out, err := Canonicalize([]byte(`{"b":1,"a":2}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != `{"a":2,"b":1}` {
		t.Fatalf("want %q, got %q", `{"a":2,"b":1}`, string(out))
	}
}

func TestCanonicalize_InvalidJSONRejected(t *testing.T) {
	_, err := Canonicalize([]byte(`{"a":1 "b":2}`))
	if err == nil {
		t.Fatalf("want ErrInvalidJSON, got nil")
	}
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("want ErrInvalidJSON, got %v", err)
	}
}

func TestCanonicalize_TopLevelScalarRejected(t *testing.T) {
	_, err := Canonicalize([]byte(`123`))
	if err == nil {
		t.Fatalf("want ErrTopLevelNotObjArray, got nil")
	}
	if !errors.Is(err, ErrTopLevelNotObjArray) {
		t.Fatalf("want ErrTopLevelNotObjArray, got %v", err)
	}
}
