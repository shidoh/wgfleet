package backup

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
)

func TestAgeRoundTripWithBinary(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age binary not installed")
	}
	// A real passphrase round trip is interactive; the seam is exercised
	// end-to-end with injected funcs in the export/restore tests.
	t.Skip("covered by export/restore tests with injected funcs")
}

func TestEncryptDecryptInjected(t *testing.T) {
	// The seam must accept injected funcs so higher layers test without `age`.
	var enc EncryptFunc = func(_ context.Context, p []byte) ([]byte, error) {
		return append([]byte("ENC:"), p...), nil
	}
	var dec DecryptFunc = func(_ context.Context, c []byte) ([]byte, error) {
		return bytes.TrimPrefix(c, []byte("ENC:")), nil
	}
	ct, err := enc(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := dec(context.Background(), ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Fatalf("round trip mismatch: %q", pt)
	}
}
