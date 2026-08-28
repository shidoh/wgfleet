package backup

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// A backup encrypted to a recipient must be restorable.
//
// AgeDecryptor ran a bare `age -d` and its comment claimed age would find the
// identity by itself. It does not: an identity comes from -i and nowhere else. So
// every archive the Web UI's button produces — that path REQUIRES a recipient — and
// every archive the operations runbook documents first were undecryptable, and the
// only way to find out was to need one.
func TestAgeDecryptorPassesTheIdentityFile(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age is not installed")
	}
	dir := t.TempDir()
	idPath := filepath.Join(dir, "key.txt")
	out, err := exec.Command("age-keygen", "-o", idPath).CombinedOutput()
	if err != nil {
		t.Skipf("age-keygen unavailable: %v: %s", err, out)
	}
	pub := ""
	for _, line := range strings.Split(string(out), "\n") {
		if _, rest, ok := strings.Cut(line, "public key: "); ok {
			pub = strings.TrimSpace(rest)
		}
	}
	if pub == "" {
		b, _ := os.ReadFile(idPath)
		for _, line := range strings.Split(string(b), "\n") {
			if _, rest, ok := strings.Cut(line, "public key: "); ok {
				pub = strings.TrimSpace(rest)
			}
		}
	}
	if pub == "" {
		t.Skip("could not determine the age public key")
	}

	plain := []byte("the controller's whole recoverable state")
	ct, err := AgeEncryptor(pub)(context.Background(), plain)
	if err != nil {
		t.Fatalf("encrypt to recipient: %v", err)
	}
	got, err := AgeDecryptor(idPath)(context.Background(), ct)
	if err != nil {
		t.Fatalf("a recipient-encrypted archive could not be restored: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("round trip changed the bytes")
	}

	// And with no identity, age must fail rather than appear to succeed.
	if _, err := AgeDecryptor("")(context.Background(), ct); err == nil {
		t.Error("decrypting a recipient archive with no identity reported success")
	}
}
