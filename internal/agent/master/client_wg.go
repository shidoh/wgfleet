package master

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/awgmod"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// --- client-facing AmneziaWG interface (the leg that used to be wg-easy's) ---
//
// The master mirror of the exit's wgPlanner, with two differences: the peers are
// end users rather than tunnels, and the backend is selectable. Everything else —
// render, compare, bring up on change, bring up when down — is the same shape,
// deliberately: this is the most sensitive interface on the fleet and it should
// behave exactly like the one the operator already trusts.

// clientWGPlanner renders and raises the master's client-facing interface.
type clientWGPlanner struct {
	confPath   string                 // awg-quick config for the client interface
	privateKey string                 // the master's client-interface private key (node-local)
	up         func(name string) bool // nil ⇒ real `ip link` probe
	awgGen     func() (int, error)    // nil ⇒ real modinfo probe (tests inject)
	// ifacePeers lists the live interface's peer public keys. nil ⇒ real `awg show`.
	ifacePeers func(name string) ([]string, error)
	// containerPresent reports whether a container exists. nil ⇒ real `docker ps`.
	containerPresent func(name string) bool
	// lookPath resolves an executable. nil ⇒ exec.LookPath (tests inject).
	lookPath func(file string) (string, error)
}

func (clientWGPlanner) Component() string { return "client AmneziaWG interface" }

func (p clientWGPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	cw := clientWGSpec(spec)
	if cw == nil {
		// wg-easy owns this leg again (the operator cleared the knob), or it always
		// did. Take the interface down ONLY if WE raised it, which is recorded in a
		// claim file rather than inferred from the interface itself.
		//
		// Identity cannot answer this question: the handover ADOPTS wg-easy's own
		// private key so that client configs keep working, which makes our public key
		// and wg-easy's the same value by design. A key comparison would therefore
		// call wg-easy's interface ours and tear it down on every pass — the exact
		// failure this branch exists to avoid.
		if !p.claimed() {
			return []reconcile.Action{reconcile.NoChangeAction("client AmneziaWG interface",
				"not managed by the agent (wg-easy owns the client leg)")}, nil
		}
		actions := []reconcile.Action{
			quickAction(domain.ClientWGBackendKernel, "down", p.confPath, true,
				"client interface handed back to wg-easy — bring ours down"),
		}
		release, err := reconcile.RemoveFileAction(p.claimPath(), "release our claim on the client interface")
		if err != nil {
			return nil, err
		}
		return append(actions, release), nil
	}
	if p.privateKey == "" {
		// Same gate as the client-vless inbound: without the key we would render a
		// config that cannot authenticate anyone. Defer rather than fail the pass.
		return []reconcile.Action{reconcile.NoChangeAction("client AmneziaWG interface",
			"pending: client interface private key not yet available")}, nil
	}
	if err := cw.Validate(); err != nil {
		// Do NOT fail the pass. This planner runs early, and the engine stops at the
		// first planner error — so an invalid client spec (a pool narrowed in the
		// manifest below an address already issued, say) would freeze mihomo, the
		// master NAT, DOCKER-USER, blocky and the VLESS inbound along with it. The
		// last-good interface config stays on disk and keeps serving; the operator
		// sees the reason in the plan and in the node's status.
		return []reconcile.Action{reconcile.NoChangeAction("client AmneziaWG interface",
			"spec rejected, keeping the last-good config: "+err.Error())}, nil
	}
	// AmneziaWG 3.x needs a 3.x kernel module. Check BEFORE rendering, exactly like
	// the exit does: writing a config we know awg setconf will reject and then
	// running awg-quick would take the CLIENT leg down, which is the one outage the
	// whole fleet notices. The userspace backend carries its own 3.x support, so the
	// gate applies only to the kernel one.
	if cw.AWG != nil && cw.AWG.AWG3Enabled() {
		// The gate applies to BOTH backends. The kernel one needs a 3.x module; the
		// userspace one needs the amneziawg-go daemon to actually be there — and
		// since awg-quick only falls back to userspace when the kernel add FAILS, a
		// node with a 1.x module and no daemon would take the config through the
		// kernel path and have it rejected. Same outage either way, so the same
		// refusal: keep the last-good config rather than write one we know fails.
		if err := p.checkBackendSupportsAWG3(cw.ResolvedBackend()); err != nil {
			return []reconcile.Action{reconcile.NoChangeAction("client AmneziaWG interface",
				"AmneziaWG 3.x refused, keeping the last-good config: "+err.Error())}, nil
		}
	}

	cfg, err := wg.RenderClientInterface(wg.ClientInterfaceInput{Spec: *cw, PrivateKey: p.privateKey})
	if err != nil {
		return nil, err
	}
	file, err := reconcile.FileAction(p.confPath, []byte(cfg), 0o600, wg.RedactConfig)
	if err != nil {
		return nil, err
	}

	actions := []reconcile.Action{file}
	backend := cw.ResolvedBackend()
	claim, err := reconcile.FileAction(p.claimPath(), []byte(claimContents), 0o600, nil)
	if err != nil {
		return nil, err
	}

	// The question is NOT "whose interface is this" — after key adoption that has no
	// answer — but "does the live interface serve what the spec says". That covers
	// every case the ownership question was meant to: a wg-easy container that
	// recreated wg0 carries wg-easy's peer list, which will not match ours, so we
	// re-apply and take it over.
	switch {
	case file.Changes():
		actions = append(actions, p.applyActions(backend, "config changed")...)
	case !p.isUp():
		actions = append(actions, p.applyActions(backend, "interface was down")...)
	case !p.servesDesiredPeers(cw):
		actions = append(actions, p.applyActions(backend, "live peers do not match the spec")...)
	default:
		if claim.Changes() {
			// Converged, but we had not recorded the claim (an upgrade from a build
			// that predates it). Record it without touching the interface.
			return append(actions, claim,
				reconcile.NoChangeAction("client AmneziaWG interface", "interface already up")), nil
		}
		return append(actions, reconcile.NoChangeAction("client AmneziaWG interface", "interface already up")), nil
	}
	actions = append(actions, claim)

	// Retire wg-easy only once we are actually carrying the leg, and only when the
	// container is still there. Doing it on the knob alone would remove the fallback
	// in the same pass where our own interface failed to come up, and doing it
	// unconditionally would report drift on every pass forever.
	if p.wgEasyPresent() {
		actions = append(actions, reconcile.BestEffortExecAction(
			"retire the wg-easy container (the agent now carries the client interface)",
			"docker", "rm", "-f", "wg-easy"))
	}
	return actions, nil
}

// applyActions brings the interface to the rendered config. Both steps are
// best-effort ON PURPOSE: this planner runs early (it must release the interface
// before the compose planner can restore wg-easy), and the reconcile engine stops
// the whole pass at the first failed action. A client interface that will not come
// up must not also freeze mihomo, the master NAT, DOCKER-USER, blocky and the
// VLESS inbound. The failure is visible as a warning and as the client-wg health
// check going red, and the next pass retries.
func (p clientWGPlanner) applyActions(backend domain.ClientWGBackend, why string) []reconcile.Action {
	return []reconcile.Action{
		quickAction(backend, "down", p.confPath, true, "bring the client interface down (if up): "+why),
		quickAction(backend, "up", p.confPath, true, "bring the client interface up: "+why),
	}
}

// userspaceImplementation is the daemon awg-quick runs when the userspace backend
// is selected. awg-quick reads it from the environment, which is why the userspace
// path goes through `sh -c` — the plan then shows the operator the exact command,
// environment included, that they could paste into a shell themselves.
const userspaceImplementation = "amneziawg-go"

// quickAction builds one awg-quick invocation for the selected backend.
func quickAction(backend domain.ClientWGBackend, verb, confPath string, bestEffort bool, summary string) reconcile.Action {
	cmd := []string{"awg-quick", verb, confPath}
	if backend == domain.ClientWGBackendUserspace {
		cmd = []string{"sh", "-c", fmt.Sprintf("WG_QUICK_USERSPACE_IMPLEMENTATION=%s awg-quick %s %s",
			userspaceImplementation, verb, shQuote(confPath))}
	}
	if bestEffort {
		return reconcile.BestEffortExecAction(summary, cmd...)
	}
	return reconcile.ExecAction(summary, cmd...)
}

// shQuote single-quotes a path for safe interpolation into an `sh -c` command.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (p clientWGPlanner) isUp() bool {
	name := clientIfaceName(p.confPath)
	if p.up == nil {
		return ipLinkUp(name)
	}
	return p.up(name)
}

// ClaimSuffix is appended to the interface config path to locate the claim file:
// the record that the AGENT raised this interface. A file, not an inference —
// see the unmanaged branch in Plan for why identity cannot answer the same
// question. Exported so the health probe reads the same path the planner writes.
const ClaimSuffix = ".claim"

// ClaimPathFor returns the claim file for an interface config.
func ClaimPathFor(confPath string) string { return confPath + ClaimSuffix }

func (p clientWGPlanner) claimPath() string { return ClaimPathFor(p.confPath) }

// claimContents is what the claim file holds. The value is immaterial — presence
// is the signal — but a sentence beats an empty file for whoever finds it.
const claimContents = "the wgfleet agent raised this client interface; removing this file does not take it down\n"

// claimed reports whether we recorded raising this interface.
func (p clientWGPlanner) claimed() bool {
	if _, err := os.Stat(p.claimPath()); err != nil {
		return false
	}
	return true
}

// servesDesiredPeers reports whether the live interface carries exactly the peers
// the spec asks for. A mismatch means somebody else configured it (a wg-easy
// container that survived a reboot) or our own apply half-failed; either way the
// answer is to re-apply.
//
// A probe that fails answers TRUE — "assume it matches". The alternative would
// bounce a healthy interface on every pass on any node where the probe cannot run,
// which is a worse failure than missing a takeover we will also catch the next
// time the config changes.
func (p clientWGPlanner) servesDesiredPeers(cw *domain.ClientWGSpec) bool {
	read := p.ifacePeers
	if read == nil {
		read = interfacePeers
	}
	live, err := read(clientIfaceName(p.confPath))
	if err != nil {
		return true
	}
	want := make(map[string]struct{}, len(cw.Clients))
	for _, c := range cw.Clients {
		want[c.PublicKey] = struct{}{}
	}
	if len(live) != len(want) {
		return false
	}
	for _, key := range live {
		if _, ok := want[key]; !ok {
			return false
		}
	}
	return true
}

// interfacePeers lists the live interface's peer public keys. `awg show <iface>
// peers` is used rather than `dump` deliberately: dump's first line carries the
// interface PRIVATE key, and a command whose output might be logged should not
// have it in hand.
func interfacePeers(name string) ([]string, error) {
	out, err := exec.Command("awg", "show", name, "peers").Output()
	if err != nil {
		return nil, err
	}
	var peers []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			peers = append(peers, line)
		}
	}
	return peers, nil
}

// wgEasyPresent reports whether a wg-easy container still exists on this host.
// Gating the retirement on it keeps an unchanged master from reporting drift
// every pass for a container that has been gone for weeks.
func (p clientWGPlanner) wgEasyPresent() bool {
	probe := p.containerPresent
	if probe == nil {
		probe = dockerContainerPresent
	}
	return probe(wgEasyContainer)
}

// wgEasyContainer is the container name the compose stack gives wg-easy.
const wgEasyContainer = "wg-easy"

func dockerContainerPresent(name string) bool {
	out, err := exec.Command("docker", "ps", "-a", "--filter", "name=^"+name+"$", "--format", "{{.Names}}").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// checkBackendSupportsAWG3 refuses an AmneziaWG 3.x config the selected backend
// cannot actually carry.
//
// The userspace backend is not a free pass. awg-quick reaches for
// WG_QUICK_USERSPACE_IMPLEMENTATION only when `ip link add … type amneziawg`
// fails, so on a node that HAS a kernel module the kernel carries the interface
// whatever the manifest says — and if that module predates 3.x the config is
// rejected and the client leg stays down. Selecting userspace therefore requires
// either a 3.x module (kernel path works) or no module and a working daemon.
func (p clientWGPlanner) checkBackendSupportsAWG3(backend domain.ClientWGBackend) error {
	kernelErr := awgmod.CheckAWG3Supported(p.awgGen)
	if backend != domain.ClientWGBackendUserspace {
		return kernelErr
	}
	if kernelErr == nil {
		return nil // the kernel module is 3.x; awg-quick will use it and that is fine
	}
	lookPath := p.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	if _, err := lookPath(userspaceImplementation); err != nil {
		return fmt.Errorf("backend is userspace but %s is not installed (%v), and the kernel module cannot carry this config: %w",
			userspaceImplementation, err, kernelErr)
	}
	// The daemon is present but the kernel module may still win the race for the
	// interface. Only a node without a usable module reliably lands on userspace.
	if !errors.Is(kernelErr, awgmod.ErrGenerationUnknown) {
		return fmt.Errorf("backend is userspace but this node has a kernel AmneziaWG module that awg-quick will use in preference to %s: %w",
			userspaceImplementation, kernelErr)
	}
	return nil
}

// interfacePublicKey asks the live interface for its own public key.
func interfacePublicKey(name string) (string, error) {
	out, err := exec.Command("awg", "show", name, "public-key").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// clientWGSpec extracts the client interface spec from a NodeSpec, or nil when
// this node is not a master or the operator has not handed the leg over.
func clientWGSpec(spec domain.NodeSpec) *domain.ClientWGSpec {
	if spec.Master == nil {
		return nil
	}
	return spec.Master.ClientWG
}

// clientIfaceName derives the interface name from the config path, the way
// awg-quick does.
func clientIfaceName(path string) string {
	return strings.TrimSuffix(filepath.Base(path), ".conf")
}

// ipLinkUp reports whether an interface exists (awg-quick creates it on `up`).
func ipLinkUp(name string) bool {
	return exec.Command("ip", "link", "show", name).Run() == nil
}
