package wg

import (
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
