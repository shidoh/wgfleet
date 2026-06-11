package provisioner

import (
	"context"
	"fmt"
	"strings"
)

// Facts are the discovered properties of a target node, gathered over SSH before
// any change is made (provisioning Phase 0). They drive both preflight checks
// and conditional bootstrap steps.
type Facts struct {
	OS           string // uname -s, e.g. "Linux"
	Arch         string // uname -m, e.g. "x86_64" / "aarch64"
	Kernel       string // uname -r
	Distro       string // ID from /etc/os-release, e.g. "ubuntu"
	HasAWGTools  bool   // awg + awg-quick present
	HasWGTools   bool   // wg + wg-quick present (vanilla WireGuard, needed for wgcf/WARP)
	HasAWGKmod   bool   // AmneziaWG kernel module available (loaded or modinfo)
	HasWgcf      bool   // wgcf present (installed from a GitHub release, not apt)
	HasNft       bool   // nftables present
	HasConntrack bool   // conntrack present
	HasZeroTier  bool   // zerotier-cli present
	HasDocker    bool   // docker engine present (needed for blocky/mihomo/wg-easy)
}

// CollectFacts gathers Facts from the target via the Runner. It never mutates
// the node — every command is read-only.
func CollectFacts(ctx context.Context, r Runner) (Facts, error) {
	var f Facts

	for _, probe := range []struct {
		cmd  string
		set  func(string)
		name string
	}{
		{"uname -s", func(s string) { f.OS = s }, "os"},
		{"uname -m", func(s string) { f.Arch = s }, "arch"},
		{"uname -r", func(s string) { f.Kernel = s }, "kernel"},
		{". /etc/os-release 2>/dev/null; printf %s \"$ID\"", func(s string) { f.Distro = s }, "distro"},
	} {
		out, err := r.Run(ctx, probe.cmd)
		if err != nil {
			return f, fmt.Errorf("collect %s: %w", probe.name, err)
		}
		probe.set(strings.TrimSpace(out))
	}

	f.HasAWGTools = commandExists(ctx, r, "awg") && commandExists(ctx, r, "awg-quick")
	f.HasWGTools = commandExists(ctx, r, "wg") && commandExists(ctx, r, "wg-quick")
	f.HasWgcf = commandExists(ctx, r, "wgcf")
	f.HasNft = commandExists(ctx, r, "nft")
	f.HasConntrack = commandExists(ctx, r, "conntrack")
	f.HasZeroTier = commandExists(ctx, r, "zerotier-cli")
	f.HasDocker = commandExists(ctx, r, "docker")
	f.HasAWGKmod = awgKmodPresent(ctx, r)

	return f, nil
}

// commandExists reports whether a binary is on the target's PATH.
func commandExists(ctx context.Context, r Runner, bin string) bool {
	// `command -v` prints the path and exits 0 when found, non-zero otherwise.
	out, err := r.Run(ctx, fmt.Sprintf("command -v %s >/dev/null 2>&1 && echo yes || echo no", bin))
	return err == nil && strings.TrimSpace(out) == "yes"
}

// awgKmodDiag reports whether the AmneziaWG kernel module is available (loaded,
// or built/installable for the running kernel) and returns a one-line diagnostic
// suitable for logs. Building it via DKMS is a pre-flight requirement we check
// rather than attempt (docs/DESIGN.md an earlier finding / open Q7).
//
// The verdict is carried by an explicit AWGKMOD=yes|no marker matched with
// Contains — NOT an exact-equality check on the output. The Runner merges the
// remote stdout and stderr into one buffer, so a stray warning on stderr (a grep
// notice, a DKMS deprecation note, an MOTD) would break a `== "yes"` comparison
// and make a present module look absent. The marker is immune to that noise.
func awgKmodDiag(ctx context.Context, r Runner) (present bool, diag string) {
	out, _ := r.Run(ctx, `k=$(uname -r); `+
		`if lsmod 2>/dev/null | grep -qw amneziawg; then echo "AWGKMOD=yes (loaded, kernel $k)"; `+
		`elif modinfo amneziawg >/dev/null 2>&1; then echo "AWGKMOD=yes (built, kernel $k)"; `+
		`else echo "AWGKMOD=no (kernel $k; not loaded; modinfo: $(modinfo amneziawg 2>&1 | head -1))"; fi`)
	diag = strings.TrimSpace(out)
	return strings.Contains(diag, "AWGKMOD=yes"), diag
}

// awgKmodPresent is the boolean form used during fact collection.
func awgKmodPresent(ctx context.Context, r Runner) bool {
	ok, _ := awgKmodDiag(ctx, r)
	return ok
}

// Preflight returns an error if the node fails a hard requirement that the
// provisioner will not auto-fix. It is surfaced, never swallowed: a missing
// AmneziaWG kernel module aborts provisioning with a clear message rather than
// producing a node that silently can't run AWG.
func (f Facts) Preflight() error {
	if !strings.EqualFold(f.OS, "Linux") {
		return fmt.Errorf("preflight: node OS is %q, only Linux is supported", f.OS)
	}
	if !f.HasAWGKmod {
		return fmt.Errorf("preflight: AmneziaWG kernel module not present " +
			"(load it or install via DKMS first — this is a pre-flight requirement, not auto-built)")
	}
	return nil
}

// MissingPackages lists the apt packages the bootstrap will need to install,
// based on what is absent. Used to render an accurate install step. wgcf and
// docker are deliberately NOT here: wgcf ships only as a GitHub-release binary
// (no apt package), and docker installs via its own script — each has its own
// dedicated bootstrap step.
func (f Facts) MissingPackages() []string {
	var pkgs []string
	if !f.HasAWGTools {
		pkgs = append(pkgs, "amneziawg-tools")
	}
	if !f.HasWGTools {
		// Vanilla WireGuard tooling: wg-quick/wg drive the wgcf WARP interface
		// (Cloudflare can't do AmneziaWG, an earlier finding), so awg-quick is not enough.
		pkgs = append(pkgs, "wireguard-tools")
	}
	if !f.HasNft {
		pkgs = append(pkgs, "nftables")
	}
	if !f.HasConntrack {
		pkgs = append(pkgs, "conntrack")
	}
	return pkgs
}
