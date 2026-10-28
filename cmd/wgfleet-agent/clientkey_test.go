package main

import (
	"io"
	"log/slog"
	"os"
	"testing"
)

func quietAgent(t *testing.T) *agent {
	t.Helper()
	return &agent{
		stateDir: t.TempDir(),
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// A master without a key file mints one and persists it, so the next pass serves
// the same identity.
func TestEnsureClientWGKeyMintsAndPersistsOnce(t *testing.T) {
	a := quietAgent(t)
	first, ephemeral, err := a.ensureClientWGKey(true)
	if err != nil {
		t.Fatalf("ensureClientWGKey() error = %v", err)
	}
	if first.PrivateKey == "" || ephemeral {
		t.Fatalf("no persistent key minted: %q (ephemeral=%v)", first.PublicKey, ephemeral)
	}
	if _, err := os.Stat(a.masterPaths().ClientWGKey); err != nil {
		t.Fatalf("the minted key was not written: %v", err)
	}
	second, _, err := a.ensureClientWGKey(true)
	if err != nil {
		t.Fatalf("second ensureClientWGKey() error = %v", err)
	}
	if second.PublicKey != first.PublicKey {
		t.Fatalf("the client identity changed between passes: %s → %s", first.PublicKey, second.PublicKey)
	}
}

// Plan mode never writes: without a key file it answers with an ephemeral key.
func TestEnsureClientWGKeyPlanWritesNothing(t *testing.T) {
	a := quietAgent(t)
	kp, ephemeral, err := a.ensureClientWGKey(false)
	if err != nil {
		t.Fatalf("ensureClientWGKey() error = %v", err)
	}
	if kp.PrivateKey == "" || !ephemeral {
		t.Fatalf("plan mode should return an ephemeral key, got %q (ephemeral=%v)", kp.PublicKey, ephemeral)
	}
	if _, err := os.Stat(a.masterPaths().ClientWGKey); err == nil {
		t.Fatal("plan mode wrote the key file")
	}
}

// Every issued client config pins the public half, so an unusable key file is a
// loud stop, never a silent re-mint.
func TestEnsureClientWGKeyRefusesAnInvalidKeyFile(t *testing.T) {
	a := quietAgent(t)
	path := a.masterPaths().ClientWGKey
	if err := writeKeyFile(path, "not-a-key"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.ensureClientWGKey(true); err == nil {
		t.Fatal("an invalid key file was accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "not-a-key\n" {
		t.Fatalf("the key file was replaced: %q (%v)", got, err)
	}
}
