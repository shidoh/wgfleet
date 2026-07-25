package hardening

import (
	"strings"
	"testing"
)

func TestSSHDConfigHasHardeningDirectives(t *testing.T) {
	for _, want := range []string{
		"PermitRootLogin prohibit-password",
		"PasswordAuthentication no",
		"KbdInteractiveAuthentication no",
		"X11Forwarding no",
	} {
		if !strings.Contains(SSHDConfig, want) {
			t.Errorf("SSHDConfig missing %q:\n%s", want, SSHDConfig)
		}
	}
}

func TestRenderFail2banJail(t *testing.T) {
	got := RenderFail2banJail([]string{"172.29.0.0/16", "10.20.3.20/32"})
	for _, want := range []string{
		"backend = systemd",
		"banaction = nftables[type=multiport]",
		"maxretry = 5",
		"[sshd]",
		"enabled = true",
		"ignoreip = 127.0.0.1/8 ::1 172.29.0.0/16 10.20.3.20/32",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("jail missing %q:\n%s", want, got)
		}
	}
}

func TestRenderFail2banJailLoopbackOnlyWhenNoCIDRs(t *testing.T) {
	if got := RenderFail2banJail(nil); !strings.Contains(got, "ignoreip = 127.0.0.1/8 ::1\n") {
		t.Fatalf("expected loopback-only ignoreip:\n%s", got)
	}
}

func TestRenderFail2banJailTrimsAndDedups(t *testing.T) {
	// Whitespace-trimmed, blanks dropped, duplicates (incl. the implicit loopback) removed.
	got := RenderFail2banJail([]string{" 172.29.0.0/16 ", "", "172.29.0.0/16", "127.0.0.1/8"})
	if !strings.Contains(got, "ignoreip = 127.0.0.1/8 ::1 172.29.0.0/16\n") {
		t.Fatalf("expected trimmed+deduped ignoreip:\n%s", got)
	}
}
