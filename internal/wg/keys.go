package wg

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// KeyPair is a WireGuard private/public key pair, base64-encoded. The private
// key is a secret that stays on the node (docs/DESIGN.md principle #2).
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKeyPair creates a fresh Curve25519 WireGuard key pair.
func GenerateKeyPair() (KeyPair, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate wg key: %w", err)
	}
	return KeyPair{PrivateKey: k.String(), PublicKey: k.PublicKey().String()}, nil
}

// PublicKeyOf derives the public key from a base64 private key.
func PublicKeyOf(privateKey string) (string, error) {
	k, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	return k.PublicKey().String(), nil
}

// ValidKey reports whether s is a well-formed base64 WireGuard key.
func ValidKey(s string) bool {
	_, err := wgtypes.ParseKey(s)
	return err == nil
}

// tunnelKeySalt namespaces the per-tunnel key derivation. It is not a secret —
// HKDF's security rests on the master private key fed in as the input keying
// material; the salt only separates this derivation from any future one over the
// same secret. Versioned so the whole per-tunnel key set can be rotated fleet-wide
// by bumping it (which is a phase-1→phase-3 roll on every exit, not a free change).
const tunnelKeySalt = "wgfleet-master-tunnel-wg-v1"

// DeriveTunnelKey derives the master's dedicated WireGuard identity for ONE
// master↔exit tunnel from its long-lived master private key and the exit's name.
//
// Why derive instead of storing N key files: the master's on-disk secret story
// stays exactly one file (wg.key), the result is reproducible after a controller
// backup/restore without adding N files to the backup set, and no new state has to
// be kept in sync with the manifest when an exit is added or renamed. The tradeoff
// is that rotating the master key rotates every per-tunnel key at once — which is
// the correct blast radius, since that key IS the master's root identity.
//
// The derived scalar is clamped the way X25519 requires (and the way
// wgtypes.GeneratePrivateKey clamps its own output): without clamping, wgtypes
// would happily accept the raw HKDF bytes as a key, but the two ends can disagree
// about the public key for a non-canonical scalar. Clamp here so PublicKeyOf on
// the derived private key always matches what the peer's kernel computes.
//
// tunnel is the EXIT NODE NAME, never a mihomo proxy name: a dual-transport exit
// renders a second "<name>-reality" proxy that carries no WireGuard key at all, and
// keying off the proxy name would derive a second, unpublished identity for it.
func DeriveTunnelKey(masterPrivateKey, tunnel string) (KeyPair, error) {
	if tunnel == "" {
		return KeyPair{}, fmt.Errorf("derive tunnel key: empty tunnel name")
	}
	root, err := wgtypes.ParseKey(masterPrivateKey)
	if err != nil {
		return KeyPair{}, fmt.Errorf("derive tunnel key for %q: parse master private key: %w", tunnel, err)
	}
	raw, err := hkdf.Key(sha256.New, root[:], []byte(tunnelKeySalt), tunnel, wgtypes.KeyLen)
	if err != nil {
		return KeyPair{}, fmt.Errorf("derive tunnel key for %q: %w", tunnel, err)
	}
	// X25519 scalar clamping (RFC 7748 §5): clear the low 3 bits, clear the top bit,
	// set the second-highest bit.
	raw[0] &= 248
	raw[31] &= 127
	raw[31] |= 64

	k, err := wgtypes.NewKey(raw)
	if err != nil {
		return KeyPair{}, fmt.Errorf("derive tunnel key for %q: %w", tunnel, err)
	}
	return KeyPair{PrivateKey: k.String(), PublicKey: k.PublicKey().String()}, nil
}

// LoadOrCreateKey returns the private key stored at path, generating and
// persisting a new one (0600) if the file does not exist. This is how an agent
// obtains a stable WG identity without the controller ever seeing the private
// key. It returns the key pair and whether a new key was created.
func LoadOrCreateKey(path string) (KeyPair, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		priv := strings.TrimSpace(string(data))
		pub, perr := PublicKeyOf(priv)
		if perr != nil {
			return KeyPair{}, false, fmt.Errorf("stored key %q invalid: %w", path, perr)
		}
		return KeyPair{PrivateKey: priv, PublicKey: pub}, false, nil
	}
	if !os.IsNotExist(err) {
		return KeyPair{}, false, fmt.Errorf("read key %q: %w", path, err)
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		return KeyPair{}, false, err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return KeyPair{}, false, fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(kp.PrivateKey+"\n"), 0o600); err != nil {
		return KeyPair{}, false, fmt.Errorf("persist key %q: %w", path, err)
	}
	return kp, true, nil
}
