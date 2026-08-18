package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// awgAptPackages are the apt packages whose installed version fixes a node's
// AmneziaWG GENERATION. They must be pinned together: AmneziaWG 3.0 changed the
// netlink attribute layout between the userspace tools and the kernel module, so
// the two sides must be on the same generation or `awg setconf` fails outright
// with "attribute type 14 has an invalid length" and the interface never comes up
// — no clients, no master↔exit tunnel (wg-easy#2723).
var awgAptPackages = []string{"amneziawg", "amneziawg-dkms", "amneziawg-tools"}

// awgHoldPlanner keeps `apt-mark hold` set on the AmneziaWG packages.
//
// This is an earlier finding ("a dependency that updates itself must be pinned") made to
// converge. The holds used to be applied by hand during fleet hardening, and a
// hand-applied invariant drifts exactly the way this one did: nodes provisioned
// later (vn1/vn2, 2026-08-05) came up with unattended-upgrades enabled and no hold
// at all, so an automatic dkms/tools bump could have flipped their AWG generation
// under a running data plane.
//
// There is deliberately NO manifest knob, unlike the sshd/fail2ban planners next
// door. `apt-mark hold` does not pin a VERSION — it only blocks automatic
// upgrades — so this planner never fights a deliberate operator upgrade
// (`apt-mark unhold && apt install && …`); it simply re-establishes the hold at
// whatever version the operator chose. A knob would therefore only ever express
// "please let unattended-upgrades change my AWG generation behind my back", which
// is the failure this exists to prevent.
type awgHoldPlanner struct {
	// state reports which of awgAptPackages are installed and which are held.
	// nil ⇒ the real dpkg-query + apt-mark probe.
	state func(ctx context.Context) (installed, held map[string]bool, err error)
	// hold applies the hold to pkgs; nil ⇒ the real `apt-mark hold`.
	hold func(ctx context.Context, pkgs []string) error
}

func (awgHoldPlanner) Component() string { return "amneziawg apt pin" }

func (p awgHoldPlanner) Plan(ctx context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	probe := p.state
	if probe == nil {
		probe = aptPackageState
	}
	installed, held, err := probe(ctx)
	if err != nil {
		// A planner that cannot see the node's state must not report convergence:
		// "no packages found" and "dpkg-query failed" look identical downstream.
		return nil, fmt.Errorf("amneziawg apt pin: read package state: %w", err)
	}

	var missing []string
	for _, pkg := range awgAptPackages {
		if installed[pkg] && !held[pkg] {
			missing = append(missing, pkg)
		}
	}
	if len(missing) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("amneziawg apt pin",
			"AmneziaWG packages already held (or not installed)")}, nil
	}
	sort.Strings(missing)

	apply := p.hold
	if apply == nil {
		apply = aptMarkHold
	}
	pkgs := append([]string(nil), missing...)
	return []reconcile.Action{reconcile.CustomAction(reconcile.ActionUpdate,
		"amneziawg apt pin",
		fmt.Sprintf("%d AmneziaWG package(s) unpinned — an automatic upgrade could split the tools/module generation", len(pkgs)),
		"apt-mark hold "+strings.Join(pkgs, " "),
		func(ctx context.Context) error { return apply(ctx, pkgs) },
	)}, nil
}

// aptPackageState probes dpkg for which of awgAptPackages are installed and
// apt-mark for which are held. A node without dpkg/apt is not an error — it is a
// node this planner has no business on, and it reports empty sets so the planner
// falls through to its no-change branch.
func aptPackageState(ctx context.Context) (installed, held map[string]bool, err error) {
	installed = make(map[string]bool, len(awgAptPackages))
	held = make(map[string]bool, len(awgAptPackages))

	args := append([]string{"-W", "-f", "${Package} ${db:Status-Status}\n"}, awgAptPackages...)
	// dpkg-query exits non-zero when ANY named package is unknown, while still
	// printing the ones it does know — so the exit code is not a failure signal
	// here and only a missing binary is.
	out, derr := exec.CommandContext(ctx, "dpkg-query", args...).Output()
	if derr != nil && len(out) == 0 {
		if isMissingBinary(derr) {
			return installed, held, nil
		}
		return nil, nil, fmt.Errorf("dpkg-query: %w", derr)
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[1] == "installed" {
			installed[f[0]] = true
		}
	}

	hout, herr := exec.CommandContext(ctx, "apt-mark", "showhold").Output()
	if herr != nil {
		if isMissingBinary(herr) {
			return installed, held, nil
		}
		return nil, nil, fmt.Errorf("apt-mark showhold: %w", herr)
	}
	sc = bufio.NewScanner(strings.NewReader(string(hout)))
	for sc.Scan() {
		if name := strings.TrimSpace(sc.Text()); name != "" {
			held[name] = true
		}
	}
	return installed, held, nil
}

func aptMarkHold(ctx context.Context, pkgs []string) error {
	out, err := exec.CommandContext(ctx, "apt-mark", append([]string{"hold"}, pkgs...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apt-mark hold %s: %w: %s", strings.Join(pkgs, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isMissingBinary(err error) bool {
	return errors.Is(err, exec.ErrNotFound)
}
