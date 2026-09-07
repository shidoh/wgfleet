package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
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
		func(ctx context.Context) error {
			err := apply(ctx, pkgs)
			// A dpkg lock held by someone else is "not now", not a failure. The
			// hold is convergent by construction — every pass re-reads the state
			// and re-applies — so the next pass 30s later sets it, by which time
			// unattended-upgrades has long finished. Failing here instead cost us
			// four spurious Error states in a week (vn1/vn2, 2026-09-03): the node
			// went Error, the alert fired, and the pass after it was already green.
			// Any OTHER failure still fails the pass: a hold that silently stops
			// being applied is exactly the drift this planner exists to prevent.
			if err != nil && (errors.Is(err, errDpkgLockBusy) || isDpkgLockBusy(err.Error())) {
				slog.Warn("amneziawg apt pin deferred: the dpkg lock is held by another process (likely unattended-upgrades); the next reconcile pass will retry",
					"packages", strings.Join(pkgs, " "), "err", err)
				return nil
			}
			return err
		},
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
	out, derr := exec.CommandContext(ctx, "dpkg-query", args...).Output()
	installed, err = dpkgInstalled(out, derr)
	if err != nil {
		return nil, nil, err
	}
	if installed == nil {
		return map[string]bool{}, held, nil // no dpkg on this node
	}

	hout, herr := exec.CommandContext(ctx, "apt-mark", "showhold").Output()
	if herr != nil {
		if isMissingBinary(herr) {
			return installed, held, nil
		}
		return nil, nil, fmt.Errorf("apt-mark showhold: %w", herr)
	}
	sc := bufio.NewScanner(strings.NewReader(string(hout)))
	for sc.Scan() {
		if name := strings.TrimSpace(sc.Text()); name != "" {
			held[name] = true
		}
	}
	return installed, held, nil
}

// dpkgInstalled reads `dpkg-query -W` output into the set of installed packages.
// nil, nil means there is no dpkg on this node at all.
//
// dpkg-query exits 1 when ANY named package is unknown, printing the ones it does
// know to stdout and "no packages found matching X" to stderr. When NONE is known
// stdout is empty and the exit code is still 1 — which the first version of this
// read as a failed probe, failing the whole reconcile pass every 30 s on a node
// whose module came from source rather than the PPA (a stand, 2026-09-07; any
// node built outside our own scripts). Exit code 1 is an answer, not an error:
// "not installed". Anything else — exit 2 (usage/database trouble) or a signal —
// stays an error, because a planner that cannot see the node must not report it
// converged.
func dpkgInstalled(out []byte, derr error) (map[string]bool, error) {
	installed := make(map[string]bool, len(awgAptPackages))
	if derr != nil {
		if isMissingBinary(derr) {
			return nil, nil
		}
		var ee *exec.ExitError
		if !errors.As(derr, &ee) || ee.ExitCode() != 1 {
			return nil, fmt.Errorf("dpkg-query: %w", derr)
		}
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[1] == "installed" {
			installed[f[0]] = true
		}
	}
	return installed, nil
}

// errDpkgLockBusy marks a hold that could not run because another process holds
// the dpkg/apt lock. Distinct from every other failure so the caller can defer
// rather than fail the pass.
var errDpkgLockBusy = errors.New("dpkg lock is held by another process")

// dpkgLockWaitSeconds is how long apt itself waits for the frontend lock before
// giving up. Short on purpose: most collisions are with unattended-upgrades and
// resolve in seconds, while the reconcile pass must not sit here — the pass
// repeats every 30s anyway, so waiting longer buys nothing and delays every
// other step behind it.
const dpkgLockWaitSeconds = 10

func aptMarkHold(ctx context.Context, pkgs []string) error {
	args := append([]string{fmt.Sprintf("-o=DPkg::Lock::Timeout=%d", dpkgLockWaitSeconds), "hold"}, pkgs...)
	out, err := exec.CommandContext(ctx, "apt-mark", args...).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if isDpkgLockBusy(text) {
			return fmt.Errorf("apt-mark hold %s: %w: %s", strings.Join(pkgs, " "), errDpkgLockBusy, text)
		}
		return fmt.Errorf("apt-mark hold %s: %w: %s", strings.Join(pkgs, " "), err, text)
	}
	return nil
}

// isDpkgLockBusy recognises the several shapes apt and dpkg use to say the same
// thing. Matching on text is unpleasant but unavoidable: both exit 100 for this
// and for a genuinely broken package operation, so the exit code cannot tell
// "come back later" apart from "this will never work".
func isDpkgLockBusy(out string) bool {
	l := strings.ToLower(out)
	if !strings.Contains(l, "lock") {
		return false
	}
	for _, marker := range []string{
		"frontend lock",
		"could not get lock",
		"unable to acquire the dpkg frontend lock",
		"lock-frontend",
		"/var/lib/dpkg/lock",
		"/var/lib/apt/lists/lock",
	} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

func isMissingBinary(err error) bool {
	return errors.Is(err, exec.ErrNotFound)
}
