package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/shidoh/wgfleet/internal/atomicfile"
	"os"
	"path/filepath"
	"strings"
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

// LoadOrCreateKey returns the exit's REALITY keypair, persisting a freshly
// generated private key (0600) on first use. Mirrors wg.LoadOrCreateKey: in apply
// mode the agent calls it to get a stable on-node identity; the private key never
// leaves the node, only the returned public key is published. created reports
// whether a new key was generated this call.
func LoadOrCreateKey(path string) (privateKey, publicKey string, created bool, err error) {
	if data, rerr := os.ReadFile(path); rerr == nil {
		priv := strings.TrimSpace(string(data))
		pub, perr := PublicKeyFor(priv)
		if perr != nil {
			return "", "", false, fmt.Errorf("stored reality key invalid: %w", perr)
		}
		return priv, pub, false, nil
	}
	priv, pub, err := GenerateKeypair()
	if err != nil {
		return "", "", false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", "", false, fmt.Errorf("create reality key dir: %w", err)
	}
	if err := atomicfile.Write(path, []byte(priv+"\n"), 0o600); err != nil {
		return "", "", false, fmt.Errorf("persist reality key: %w", err)
	}
	return priv, pub, true, nil
}

// ValidPublicKey reports whether s is a well-formed REALITY x25519 public key: a
// base64.RawURLEncoding string decoding to exactly 32 bytes. The controller
// validates it before storing because it is rendered verbatim into config
// (reality-opts.public-key), so a malformed/multi-line value must be rejected.
func ValidPublicKey(s string) bool {
	raw, err := realityKeyEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
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
