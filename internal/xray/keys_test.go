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
