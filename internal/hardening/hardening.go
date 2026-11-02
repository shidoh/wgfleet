// Package hardening holds the canonical host-hardening artifacts — the sshd
// drop-in and the fail2ban sshd jail — shared by the controller's bootstrap
// provisioner (which installs them on a new node) and the agent's reconcile loop
// (which continuously re-asserts them). One source of truth means bootstrap and
// reconcile render byte-identical files, so a hand-edit or a partial overwrite is
// repaired on the next reconcile pass rather than drifting until the next
// re-provision. A partial overwrite of the sshd drop-in once silently re-enabled
// password auth fleet-wide; the reconcile planner exists to catch that.
package hardening

import (
	"fmt"
	"net/netip"
	"strings"
)

// Canonical on-node paths. Both bootstrap and the agent host planners write here,
// so a reconcile pass converges exactly what bootstrap laid down.
const (
	SSHDDropInPath   = "/etc/ssh/sshd_config.d/10-wgfleet-hardening.conf"
	Fail2banJailPath = "/etc/fail2ban/jail.d/wgfleet.conf"
)

// SSHDConfig is the managed sshd drop-in: key-only auth, no root password login,
// no X11 forwarding. Placed in sshd_config.d so it overrides distro defaults
// without rewriting the main config.
const SSHDConfig = `# Managed by wgfleet — sshd hardening. Reconciled; do not hand-edit.
PermitRootLogin prohibit-password
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
`

// fail2banJail is the sshd jail template. %s is the ignoreip list (loopback + the
// management overlay). It coexists with the wgfleet nft ruleset: fail2ban's
// nftables action manages its OWN table, and a ban DROP there is terminal
// regardless of the wgfleet accept at the same hook, so banned scanners are
// dropped while legitimate (key-auth) logins are never touched.
const fail2banJail = `# Managed by wgfleet — SSH brute-force protection. Reconciled; do not hand-edit.
[DEFAULT]
backend = systemd
banaction = nftables[type=multiport]
bantime = 1h
findtime = 10m
maxretry = 5
# Never ban loopback or the management overlay: the operator and control plane
# reach nodes over it. Key auth never fails so a ban is unlikely anyway — this is
# belt-and-suspenders against self-lockout.
ignoreip = %s

[sshd]
enabled = true
`

// RenderFail2banJail fills the sshd jail's ignoreip with loopback plus every
// management-overlay CIDR, so the operator/control plane reaching a node over the
// overlay is never banned. Entries that are not a valid IP or CIDR are dropped
// (defensive: this is exported and interpolates into a config file), as are blanks
// and duplicates; input order is otherwise preserved so the rendered file is stable
// across reconcile passes.
func RenderFail2banJail(mgmtIgnoreCIDRs []string) string {
	parts := []string{"127.0.0.1/8", "::1"}
	seen := map[string]struct{}{"127.0.0.1/8": {}, "::1": {}}
	for _, c := range mgmtIgnoreCIDRs {
		c = strings.TrimSpace(c)
		if c == "" || !validIgnoreEntry(c) {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		parts = append(parts, c)
	}
	return fmt.Sprintf(fail2banJail, strings.Join(parts, " "))
}

// validIgnoreEntry reports whether s is a bare IP address or a CIDR prefix — the
// only forms fail2ban's ignoreip accepts. Anything else (a hostname, a stray
// newline, garbage) is rejected so it cannot corrupt the rendered jail.
func validIgnoreEntry(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(s)
	return err == nil
}
