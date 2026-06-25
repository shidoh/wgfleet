package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// realityKeyEncoding is the base64 alphabet REALITY/xray use for x25519 keys.
// NOTE: this is base64.RawURLEncoding (no padding, URL-safe) — DIFFERENT from
// WireGuard, which uses standard base64. `xray x25519` and mihomo
// reality-opts.public-key both expect this encoding; getting it wrong makes the
// REALITY handshake fail silently. Verified by the live smoke test (ADR-0025).
var realityKeyEncoding = base64.RawURLEncoding

// GenerateKeypair generates a fresh REALITY x25519 keypair, returning the private
// and public keys base64-encoded in the REALITY/xray convention. The private key
// stays on the exit; only the public key is published to the controller (keybroker
// principle #2).
func GenerateKeypair() (privateKey, publicKey string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate reality keypair: %w", err)
	}
	return realityKeyEncoding.EncodeToString(priv.Bytes()),
		realityKeyEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// PublicKeyFor derives the REALITY public key from a base64 private key, so the
// agent can re-publish the pubkey from a persisted private key without storing the
// pubkey separately.
func PublicKeyFor(privateKey string) (string, error) {
	raw, err := realityKeyEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode reality private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid reality private key: %w", err)
	}
	return realityKeyEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}
