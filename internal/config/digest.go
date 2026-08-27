package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Manifest digests answer one question the control plane could not answer before:
// is the running controller on the configuration that is on disk?
//
// It goes wrong in more ways than the obvious one. The operator edits and forgets
// to apply; applies on the wrong host; leaves an edit half-written; or the
// controller itself rewrites the file (a transport switch from the Web UI does,
// see SetExitActiveTransport). Until now every one of those surfaced at the NEXT
// restart, which is to say by accident, possibly weeks later and to a different
// person.

// DigestFile returns the SHA-256 of a file's bytes, hex-encoded.
//
// Deliberately the raw file, not the parsed config: the comparison has to catch a
// half-written edit and a comment-only change too. An operator who changed
// something and did not apply it wants to be told, whatever they changed.
func DigestFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Effective is the digest of the manifest THIS process is running on. It is set
// once at load and updated only when the controller itself rewrites the manifest
// — without that update a transport switch from the Web UI would show as drift
// forever, and a drift signal that cries wolf is worse than none.
type Effective struct {
	mu     sync.RWMutex
	digest string
}

func (e *Effective) Set(digest string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.digest = digest
}

// Digest returns the loaded manifest's digest, or "" before one is recorded.
func (e *Effective) Digest() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.digest
}

// EffectiveFile is where the running controller records the manifest it loaded.
// A separate process — `--support-bundle`, `--provision`, a human with `cat` —
// can then answer "what is the controller actually running on" without asking the
// controller, which is the whole point: the question comes up precisely when the
// controller is not behaving as the file on disk says it should.
const EffectiveFile = "/run/wgfleet/controller.effective"

// WriteEffective records the digest and when it was loaded. Best-effort by
// design: /run may be absent or read-only in a container or a test, and a
// controller must not refuse to serve because it could not write a breadcrumb.
// The caller logs the failure; drift reporting still works from memory.
func WriteEffective(path, digest string, loadedAt time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf("digest %s\nloaded_at %s\npid %d\n",
		digest, loadedAt.UTC().Format(time.RFC3339), os.Getpid())
	return os.WriteFile(path, []byte(body), 0o644)
}

// ReadEffectiveDigest returns the digest recorded by the running controller, or
// "" when there is no record (no controller running here, or an older build).
func ReadEffectiveDigest(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "digest "); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
