package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretResolveEnv(t *testing.T) {
	t.Setenv("MY_CA_KEY", "top-secret-pem")
	got, err := Secret("env://MY_CA_KEY").Resolve(nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "top-secret-pem" {
		t.Errorf("got %q", got)
	}
}

func TestSecretResolveProvider(t *testing.T) {
	t.Setenv("WGFLEET_SECRET_CA_KEY", "provider-secret")
	got, err := Secret("secret://ca-key").Resolve(EnvSecretProvider{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "provider-secret" {
		t.Errorf("got %q", got)
	}
}

func TestSecretFilePermissionGuard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Secret("file://" + path).Resolve(nil); err == nil {
		t.Fatal("expected permission error for 0644 secret file")
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Secret("file://" + path).Resolve(nil)
	if err != nil {
		t.Fatalf("resolve 0600 file: %v", err)
	}
	if got != "secret" {
		t.Errorf("got %q (want trimmed 'secret')", got)
	}
}

func TestSecretInlineAndReference(t *testing.T) {
	got, err := Secret("inline-value").Resolve(nil)
	if err != nil || got != "inline-value" {
		t.Fatalf("inline resolve: %q, %v", got, err)
	}
	if Secret("inline-value").IsReference() {
		t.Error("inline value should not be a reference")
	}
	if !Secret("secret://x").IsReference() {
		t.Error("secret:// should be a reference")
	}
}
