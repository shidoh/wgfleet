package wgeasy

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AdminUsername is the wg-easy admin account name created during unattended
// setup. It is not a secret (only the password is), so it is a fixed constant the
// operator can rely on when logging into the wg-easy UI.
const AdminUsername = "admin"

// adminPasswordLen is the length of a generated wg-easy admin password. 24 base62
// characters is ~142 bits of entropy — well beyond brute force for a UI login.
const adminPasswordLen = 24

// base62 is the alphabet for generated passwords: unambiguous, shell-safe, and
// never quoted by the YAML encoder (so the rendered compose env stays one line,
// which keeps the plan redactor simple).
const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GeneratePassword returns a cryptographically random base62 password for the
// wg-easy admin account.
func GeneratePassword() (string, error) {
	buf := make([]byte, adminPasswordLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate wg-easy admin password: %w", err)
	}
	for i, b := range buf {
		buf[i] = base62[int(b)%len(base62)]
	}
	return string(buf), nil
}

// ReadAdminPassword reads a previously persisted admin password from path. It
// returns os.ErrNotExist (wrapped) when the file is absent so callers can decide
// whether to generate one.
func ReadAdminPassword(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	pass := strings.TrimSpace(string(data))
	if pass == "" {
		return "", fmt.Errorf("wg-easy admin password file %q is empty", path)
	}
	return pass, nil
}

// LoadOrCreateAdminPassword returns the admin password persisted at path,
// generating and writing a fresh one (0600) on first use. created reports whether
// a new password was generated. The password never leaves the node: it is
// injected into wg-easy's INIT_PASSWORD by the agent and is the credential the
// operator reads back over SSH (ADR-0008 — the controller never sees it).
func LoadOrCreateAdminPassword(path string) (password string, created bool, err error) {
	if pass, rerr := ReadAdminPassword(path); rerr == nil {
		return pass, false, nil
	} else if !os.IsNotExist(rerr) {
		return "", false, fmt.Errorf("read wg-easy admin password: %w", rerr)
	}
	pass, err := GeneratePassword()
	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", false, fmt.Errorf("create wg-easy admin password dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(pass+"\n"), 0o600); err != nil {
		return "", false, fmt.Errorf("write wg-easy admin password %q: %w", path, err)
	}
	return pass, true, nil
}
