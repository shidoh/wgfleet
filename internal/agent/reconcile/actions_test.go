package reconcile

import (
	"os"
	"path/filepath"
	"testing"
)

// A redactor declares the content secret-bearing. Redaction only affects the
// dry-run Display string — the real bytes hit the disk — so the mode is the only
// at-rest protection. Shipping 0644 alongside a redactor is how the master's
// mihomo config went out world-readable carrying one WireGuard private key per
// exit, and the master compose file carrying the wg-easy admin password.
func TestFileActionRefusesWorldReadableSecrets(t *testing.T) {
	redact := func(s string) string { return "REDACTED" }
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		_, err := FileAction(filepath.Join(t.TempDir(), "secret.yaml"), []byte("private-key: x"), mode, redact)
		if err == nil {
			t.Errorf("mode %#o with a redactor must be refused", mode)
		}
	}
	if _, err := FileAction(filepath.Join(t.TempDir(), "secret.yaml"), []byte("private-key: x"), 0o600, redact); err != nil {
		t.Errorf("0600 with a redactor must be allowed: %v", err)
	}
	// No redactor ⇒ not secret-bearing ⇒ a readable mode stays legal (nftables
	// rulesets, direct-networks lists and the like are deliberately world-readable).
	if _, err := FileAction(filepath.Join(t.TempDir(), "public.conf"), []byte("x"), 0o644, nil); err != nil {
		t.Errorf("0644 without a redactor must remain allowed: %v", err)
	}
}
