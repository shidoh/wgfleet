package xray

import "testing"

func TestGenerateKeypairRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if priv == "" || pub == "" || priv == pub {
		t.Fatalf("degenerate keypair: priv=%q pub=%q", priv, pub)
	}
	got, err := PublicKeyFor(priv)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	if got != pub {
		t.Errorf("PublicKeyFor(priv) = %q, want %q", got, pub)
	}
	// Distinct each call.
	priv2, _, _ := GenerateKeypair()
	if priv2 == priv {
		t.Error("two generated private keys are identical")
	}
}

func TestPublicKeyForRejectsGarbage(t *testing.T) {
	if _, err := PublicKeyFor("!!!not-base64!!!"); err == nil {
		t.Error("expected error for invalid base64 private key")
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/reality.key"
	priv, pub, created, err := LoadOrCreateKey(path)
	if err != nil || !created {
		t.Fatalf("first LoadOrCreateKey: created=%v err=%v", created, err)
	}
	// Second call loads the SAME persisted key (created=false, stable identity).
	priv2, pub2, created2, err := LoadOrCreateKey(path)
	if err != nil || created2 {
		t.Fatalf("second LoadOrCreateKey: created=%v err=%v", created2, err)
	}
	if priv2 != priv || pub2 != pub {
		t.Errorf("key not stable across loads: priv %q→%q pub %q→%q", priv, priv2, pub, pub2)
	}
	// Derived pubkey matches.
	if got, _ := PublicKeyFor(priv); got != pub {
		t.Errorf("persisted priv derives %q, want %q", got, pub)
	}
}
