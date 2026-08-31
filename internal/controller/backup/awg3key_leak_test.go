package backup

import (
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
