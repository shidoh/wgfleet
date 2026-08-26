package master

import (
	"context"
	"fmt"
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
	// ifaceKey reads the public key of the LIVE interface. nil ⇒ real `awg show`.
	// It answers the question the existence probe cannot: an interface named wg0
	// may be ours or may be wg-easy's, and the two demand opposite actions.
	ifaceKey func(name string) (string, error)
}

func (clientWGPlanner) Component() string { return "client AmneziaWG interface" }

func (p clientWGPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	cw := clientWGSpec(spec)
	if cw == nil {
		// wg-easy owns this leg again (the operator cleared the knob), or it always
		// did. Take the interface down ONLY if it is ours: on a master we never
		// managed — and on the rollback pass, where the compose planner has already
		// restored wg-easy and let it recreate wg0 — the live interface belongs to
		// wg-easy, and tearing it down would break the client leg on every pass
		// forever, because our config file deliberately stays on disk.
		if p.ownsInterface() {
			// The backend is unknown here (the spec is gone), so use the kernel form:
			// awg-quick down works for either implementation, since taking an
			// interface down does not need the userspace daemon.
			return []reconcile.Action{quickAction(domain.ClientWGBackendKernel, "down", p.confPath, true,
				"client interface handed back to wg-easy — bring ours down")}, nil
		}
		return []reconcile.Action{reconcile.NoChangeAction("client AmneziaWG interface",
			"not managed by the agent (wg-easy owns the client leg)")}, nil
	}
	if p.privateKey == "" {
		// Same gate as the client-vless inbound: without the key we would render a
		// config that cannot authenticate anyone. Defer rather than fail the pass.
		return []reconcile.Action{reconcile.NoChangeAction("client AmneziaWG interface",
			"pending: client interface private key not yet available")}, nil
	}
	if err := cw.Validate(); err != nil {
		return nil, fmt.Errorf("client interface spec: %w", err)
	}
	// AmneziaWG 3.x needs a 3.x kernel module. Check BEFORE rendering, exactly like
	// the exit does: writing a config we know awg setconf will reject and then
	// running awg-quick would take the CLIENT leg down, which is the one outage the
	// whole fleet notices. The userspace backend carries its own 3.x support, so the
	// gate applies only to the kernel one.
	if cw.ResolvedBackend() == domain.ClientWGBackendKernel && cw.AWG != nil && cw.AWG.AWG3Enabled() {
		if err := awgmod.CheckAWG3Supported(p.awgGen); err != nil {
			return nil, err
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
	switch {
	case file.Changes():
		// A credential was issued, revoked or muted, or the interface itself moved.
		// down is best-effort: on the first pass there is nothing to bring down.
		actions = append(actions,
			quickAction(backend, "down", p.confPath, true, "bring the client interface down (if up)"),
			quickAction(backend, "up", p.confPath, false, "bring the client interface up with the new config"))
	case !p.isUp():
		actions = append(actions,
			quickAction(backend, "up", p.confPath, false, "bring the client interface up (it was down)"))
	case !p.ownsInterface():
		// Something else is holding wg0 — in practice a wg-easy container that
		// survived the handover and recreated it after a reboot. The config has not
		// changed, so without this branch the pass reports "already up" while end
		// users authenticate against wg-easy's peer list: converged, green and wrong.
		actions = append(actions,
			quickAction(backend, "down", p.confPath, true, "reclaim the client interface (another implementation holds it)"),
			quickAction(backend, "up", p.confPath, false, "bring the client interface up (reclaimed)"))
	default:
		actions = append(actions, reconcile.NoChangeAction("client AmneziaWG interface", "interface already up"))
	}
	return actions, nil
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

// ownsInterface reports whether the LIVE interface is the one we rendered — i.e.
// whether its public key is derived from our private key.
//
// A probe that fails answers false. That asymmetry is deliberate: "false" leads
// to bringing an interface up or leaving somebody else's alone, while "true"
// authorises a teardown. When we cannot tell, we must not tear down.
func (p clientWGPlanner) ownsInterface() bool {
	if !p.isUp() || p.privateKey == "" {
		return false
	}
	want, err := wg.PublicKeyOf(p.privateKey)
	if err != nil {
		return false
	}
	read := p.ifaceKey
	if read == nil {
		read = interfacePublicKey
	}
	got, err := read(clientIfaceName(p.confPath))
	if err != nil {
		return false
	}
	return strings.TrimSpace(got) == want
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
