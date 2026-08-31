package backup

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
)

// An operator who writes the secret inline — which nothing refuses, and which the
// startup message practically invites by saying `openssl rand -base64 48` — used to
// have it treated as a FILE PATH. Warnings then stat()ed it, failed, and formatted
// the secret itself into the message with %s. That message goes to stderr, to the
// journal (the console's Backup button), and from there into a support bundle, where
// the scrubber cannot catch it: it arrives as prose with no key= anchor to match.
// The fleet-wide header-protection secret must never appear in a warning.
func TestInlineAWG3KeyNeverReachesAWarning(t *testing.T) {
	const secret = "S3cr3tHeaderProtectionKeyMaterialAAAABBBBCCCC=="
	cfg := &config.ControllerConfig{}
	cfg.Fleet.AWG3Key = config.Secret(secret)

	if p := awg3KeyPath(cfg); strings.Contains(p, secret) {
		t.Errorf("awg3KeyPath treated the secret as a path: %q", p)
	}

	src := Sources{}
	for _, w := range src.Warnings(cfg) {
		if strings.Contains(w, secret) {
			t.Fatalf("the secret is printed in a warning: %q", w)
		}
	}
}

// controller.yaml holds WG/REALITY private keys and the admin password. Three other
// places force it to 0600; restore used to write it 0644 on a DR host — the one
// machine where an operator then runs other commands.
func TestRestoreKeepsTheManifestOwnerOnly(t *testing.T) {
	for _, tc := range []struct {
		dest string
		want uint32
	}{
		{"/etc/wgfleet/controller.yaml", 0o600},
		{"/etc/wgfleet/ca.key", 0o600},
		{"/etc/wgfleet/state.db", 0o600},
		{"/etc/wgfleet/ca.crt", 0o644},
		{"/etc/wgfleet/agent.yaml", 0o644},
	} {
		if got := uint32(destMode(tc.dest)); got != tc.want {
			t.Errorf("destMode(%s) = %o, want %o", tc.dest, got, tc.want)
		}
	}
}

// A bare relative filename is a legitimate spelling and must keep travelling; only
// inline key material must be refused. Detection is by the FILESYSTEM, not by the
// shape of the string — a shape heuristic classified more than a third of real
// `openssl rand -base64 48` secrets as filenames, because that is exactly 64
// characters with no padding and `/` is a legal base64 character.
func TestPathDetectionUsesTheFilesystemNotTheShape(t *testing.T) {
	dir := t.TempDir()
	bare := "awg3.key"
	if err := os.WriteFile(filepath.Join(dir, bare), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	// A bare name that exists is a path.
	cfg := &config.ControllerConfig{}
	cfg.Fleet.AWG3Key = config.Secret(bare)
	if awg3KeyPath(cfg) == "" {
		t.Errorf("%q exists on disk but was not recognised as a path", bare)
	}
	// An absolute path that exists is a path.
	abs := filepath.Join(dir, "abs.key")
	if err := os.WriteFile(abs, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2 := &config.ControllerConfig{}
	cfg2.Fleet.AWG3Key = config.Secret(abs)
	if awg3KeyPath(cfg2) == "" {
		t.Errorf("%q exists but was not recognised as a path", abs)
	}
	// A path that does NOT exist is not trusted on its face — `/` is in the base64
	// alphabet, so an absolute-looking value can be a secret.
	cfg3 := &config.ControllerConfig{}
	cfg3.Fleet.AWG3Key = config.Secret("/etc/wgfleet/does-not-exist.key")
	if awg3KeyPath(cfg3) != "" {
		t.Error("a non-existent path was trusted by its prefix alone")
	}
}

// The measured failure: real secrets, generated the way the product tells operators
// to, must never be treated as filenames — and must never reach a warning.
func TestRealAWG3SecretsAreNeverTreatedAsPaths(t *testing.T) {
	for i := 0; i < 500; i++ {
		raw := make([]byte, 48)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		secret := base64.StdEncoding.EncodeToString(raw) // `openssl rand -base64 48`

		cfg := &config.ControllerConfig{}
		cfg.Fleet.AWG3Key = config.Secret(secret)
		if p := awg3KeyPath(cfg); p != "" {
			t.Fatalf("an inline secret was treated as a path: %q", p)
		}
		for _, w := range (Sources{}).Warnings(cfg) {
			if strings.Contains(w, secret) {
				t.Fatalf("a secret reached a warning: %q", w)
			}
		}
	}
}
