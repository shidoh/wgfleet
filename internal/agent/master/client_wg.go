package master

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/agent/wgiface"
	"github.com/shidoh/wgfleet/internal/awgmod"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// --- client-facing AmneziaWG interface ---
//
// The master mirror of the exit's wgPlanner, with two differences: the peers are
// end users rather than tunnels, and the backend is selectable. Everything else —
// render, compare, bring up on change, bring up when down — is the same shape,
// deliberately: this is the most sensitive interface on the fleet and it should
// behave exactly like the one the operator already trusts.

// clientWGPlanner renders and raises the master's client-facing interface.
type clientWGPlanner struct {
	confPath   string // awg-quick config for the client interface
	privateKey string // the master's client-interface private key (node-local)
	// synthKey is the keypair of the master's OWN client: the peer it sends traffic
	// through to measure whether a packet entering this interface comes back. Zero
	// value ⇒ no prober, and the interface renders exactly as it did before.
	synthKey wg.KeyPair
	up       func(name string) bool // nil ⇒ real `ip link` probe
	awgGen   func() (int, error)    // nil ⇒ real modinfo probe (tests inject)
	// ifacePeers lists the live interface's peer public keys. nil ⇒ real `awg show`.
	ifacePeers func(name string) ([]string, error)
	// lookPath resolves an executable. nil ⇒ exec.LookPath (tests inject).
	lookPath func(file string) (string, error)
}

func (clientWGPlanner) Component() string { return "client AmneziaWG interface" }

func (p clientWGPlanner) Plan(_ context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	cw := clientWGSpec(spec)
	if cw == nil {
		// The spec has no client interface for this master. Take ours down ONLY if
		// WE raised it, which is recorded in a claim file rather than inferred from
		// the interface itself.
		if !p.claimed() {
			return []reconcile.Action{reconcile.NoChangeAction("client AmneziaWG interface",
				"no client interface in the spec")}, nil
		}
		actions := []reconcile.Action{
			wgiface.QuickAction(domain.ClientWGBackendKernel, "down", p.confPath, true,
				"no client interface in the spec — bring ours down"),
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
		return p.deferred("pending: client interface private key not yet available"), nil
	}
	if err := cw.Validate(); err != nil {
		// Do NOT fail the pass. This planner runs early, and the engine stops at the
		// first planner error — so an invalid client spec (a pool narrowed in the
		// manifest below an address already issued, say) would freeze mihomo, the
		// master NAT, DOCKER-USER, blocky and the VLESS inbound along with it. The
		// last-good interface config stays on disk and keeps serving; the operator
		// sees the reason in the plan and in the node's status.
		return p.deferred("spec rejected, keeping the last-good config: " + err.Error()), nil
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
			return p.deferred("AmneziaWG 3.x refused, keeping the last-good config: " + err.Error()), nil
		}
	}

	// The prober joins the peer list here rather than upstream, because its key is
	// node-local and the controller has never seen it. Everything downstream that
	// compares live peers against "the spec" therefore has to compare against THIS
	// one — see servesDesiredPeers, which takes the same augmented value.
	rendered := wg.WithSyntheticPeer(*cw, p.syntheticPeer(*cw))
	cfg, err := wg.RenderClientInterface(wg.ClientInterfaceInput{Spec: rendered, PrivateKey: p.privateKey})
	if err != nil {
		return nil, err
	}
	prevRaw, _ := os.ReadFile(p.confPath)
	prevCfg := string(prevRaw)
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

	// The question is "does the live interface serve what the spec says": an
	// interface someone else recreated carries a different peer list, which will not
	// match ours, so we re-apply and take it over.
	// A spec with zero clients is APPLIED, not refused.
	//
	// This used to defer, on the theory that "serve nobody" could only come from a
	// controller that had failed to read its credential store. It is also, exactly,
	// what the operator revoking or pausing their last credential produces — and the
	// agent cannot tell those apart from the spec, because they are the same spec.
	// So the refusal turned Revoke into a no-op that reported success: the UI said
	// done, the planner declined on that pass and every pass after it, and the
	// revoked peer stayed on the live interface. A revocation that does not revoke
	// is worse than any failure it was guarding against.
	//
	// It also would not have caught what it was written for. The controller cannot
	// produce that spec: a store failure fails the whole render and the node keeps
	// its last-good config (11e785b, keybroker/client_wg.go). No RELEASED controller
	// ever could — keybroker/client_wg.go exists in no tag, so the only builds with
	// the old behaviour are dev commits from a 20-hour unreleased window. And the
	// check fired at EXACTLY zero, so a controller rendering one client instead of
	// nine went straight through it. It read like a floor and was a tripwire on one
	// arity.
	//
	// The controller is the authority on who its clients are. Absence of the whole
	// block remains a different instruction — "no client interface" — handled above.
	// Removing every live peer is still worth a line in the journal, so it is
	// summarised rather than silent.
	if live, known := p.livePeerCount(); known && live > 0 && len(cw.Clients) == 0 {
		actions = append(actions, reconcile.NoChangeAction("client AmneziaWG interface",
			fmt.Sprintf("the spec has no clients: removing all %d live peer(s)", live)))
	}

	// Past every deferral: whatever the last pass declined to do, it is doing it now.
	actions = append(actions, p.clearDeferred())

	peersMatch, _ := p.servesDesiredPeers(&rendered)
	// Before deciding to recreate the device: can this be done as a peer edit?
	//
	// `awg-quick down` + `up` destroys the interface, and with it every established
	// session on it — every client device on the master loses its tunnel and
	// re-handshake. That is a fair price for an interface-level change, which cannot
	// be applied any other way. It is not a fair price for adding one peer, and the
	// upgrade that introduces the path prober adds exactly one: every client on the
	// fleet would have paid for a measurement peer.
	if (file.Changes() || !peersMatch) && p.isUp() {
		if delta := p.peerDeltaActions(&rendered, prevCfg, cfg); delta != nil {
			return append(actions, delta...), nil
		}
	}
	switch {
	case file.Changes():
		return append(actions, p.applyActions(backend, "config changed")...), nil
	case !p.isUp():
		return append(actions, p.applyActions(backend, "interface was down")...), nil
	case !peersMatch:
		return append(actions, p.applyActions(backend, "live peers do not match the spec")...), nil
	}

	// Converged. An interface that is up and serving our peers without a claim is
	// the upgrade path from a build predating the claim: record it.
	if claim.Changes() {
		return append(actions, claim,
			reconcile.NoChangeAction("client AmneziaWG interface", "interface already up")), nil
	}
	return append(actions, reconcile.NoChangeAction("client AmneziaWG interface", "interface already up")), nil
}

// applyActions brings the interface to the rendered config. Both steps are
// best-effort ON PURPOSE: this planner runs early, and the reconcile engine stops
// the whole pass at the first failed action. A client interface that will not come
// up must not also freeze mihomo, the master NAT, DOCKER-USER, blocky and the
// VLESS inbound. The failure is visible as a warning and as the client-wg health
// check going red, and the next pass retries.
func (p clientWGPlanner) applyActions(backend domain.ClientWGBackend, why string) []reconcile.Action {
	// The claim is a RECEIPT for a successful bring-up, not a record that one was
	// attempted: the client-wg-owned health check and the peer-edit path read it as
	// proof the agent carries the interface, so a failed `awg-quick up` must not
	// produce one.
	//
	// OnApplied fires only when the exec really succeeded; BestEffort then keeps a
	// failure from aborting the pass, which is why the order matters.
	up := wgiface.QuickAction(backend, "up", p.confPath, false, "bring the client interface up: "+why).
		OnApplied(p.recordClaim).
		BestEffort()
	return []reconcile.Action{
		wgiface.QuickAction(backend, "down", p.confPath, true, "bring the client interface down (if up): "+why),
		up,
	}
}

// livePeerCount reports how many peers the live interface serves, and whether it
// could be asked. Separate from servesDesiredPeers because that one fails OPEN on
// a probe error, which is right for "should I re-apply" and wrong for "may I drop
// every peer".
func (p clientWGPlanner) livePeerCount() (n int, known bool) {
	read := p.ifacePeers
	if read == nil {
		read = wgiface.Peers
	}
	live, err := read(wgiface.Name(p.confPath))
	if err != nil {
		return 0, false
	}
	return len(live), true
}

// deferredPath is where the planner records WHY it is not applying the spec.
//
// It exists because the client-wg-owned health check could not see a deferral at
// all: it probes the claim file and `ip link show`, and once the interface is up
// both stay true forever. So "no key yet", "spec rejected" and "3.x
// refused" all reported green — including the case where a single malformed
// credential freezes the interface and every later revocation silently stops
// taking effect while the UI reports success. A check that reads the world cannot
// see a decision the planner made; it has to read the planner's verdict.
func (p clientWGPlanner) deferredPath() string { return wgiface.DeferredPath(p.confPath) }

// deferral is the shared marker this planner and the exit's lifeline both write;
// the mechanism lives in wgiface so the ".deferred" suffix the health probes read
// has exactly one owner.
func (p clientWGPlanner) deferral() wgiface.Deferral {
	return wgiface.Deferral{Path: p.deferredPath(), Component: "client AmneziaWG interface"}
}

// deferred returns the plan for a pass that declines to apply, recording the
// reason where the health check can find it.
func (p clientWGPlanner) deferred(reason string) []reconcile.Action {
	return p.deferral().Write(reason)
}

// clearDeferred removes the marker once the planner is applying or converged.
func (p clientWGPlanner) clearDeferred() reconcile.Action { return p.deferral().Clear() }

// recordClaim writes the claim file. Best-effort by design: failing to record it
// costs a redundant re-apply next pass, whereas failing the pass here would take
// the master's other subsystems down with it.
func (p clientWGPlanner) recordClaim() {
	if err := os.WriteFile(p.claimPath(), []byte(claimContents), 0o600); err != nil {
		slog.Warn("could not record the client interface claim", "path", p.claimPath(), "err", err)
	}
}

func (p clientWGPlanner) isUp() bool {
	name := wgiface.Name(p.confPath)
	if p.up == nil {
		return wgiface.IsUp(name)
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
// the spec asks for. A mismatch means somebody else configured it (something
// that raised wg0 again after a reboot) or our own apply half-failed; either way the
// answer is to re-apply.
//
// A probe that fails answers TRUE — "assume it matches". The alternative would
// bounce a healthy interface on every pass on any node where the probe cannot run,
// which is a worse failure than missing a takeover we will also catch the next
// time the config changes.
// servesDesiredPeers reports whether the live interface serves exactly the spec's
// peers, and whether it could be asked at all. The second return matters: a probe
// that cannot run must not be read as "matches" by a caller about to delete the
// only fallback, even though it is correctly read that way by the caller deciding
// whether to re-apply (where failing open avoids a pointless interface bounce).
func (p clientWGPlanner) servesDesiredPeers(cw *domain.ClientWGSpec) (matches, known bool) {
	return wgiface.ServesPeers(wgiface.Name(p.confPath), cw.Clients, p.ifacePeers)
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
	if _, err := lookPath(wgiface.UserspaceImplementation); err != nil {
		return fmt.Errorf("backend is userspace but %s is not installed (%v), and the kernel module cannot carry this config: %w",
			wgiface.UserspaceImplementation, err, kernelErr)
	}
	// The daemon is present but the kernel module may still win the race for the
	// interface. Only a node without a usable module reliably lands on userspace.
	if !errors.Is(kernelErr, awgmod.ErrGenerationUnknown) {
		return fmt.Errorf("backend is userspace but this node has a kernel AmneziaWG module that awg-quick will use in preference to %s: %w",
			wgiface.UserspaceImplementation, kernelErr)
	}
	return nil
}

// InterfacePublicKey asks the live interface for its own public key.
//
// The client-identity audit checks "the key I publish" against "the key actually
// answering handshakes".
//
// `public-key`, not `dump`: the dump's first line carries the interface PRIVATE
// key, and this is called from a path that logs.
func InterfacePublicKey(name string) (string, error) {
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

// ClientInterfaceUp reports whether the master's client-facing interface exists
// at all. The namespace mover asks before it reads a failing client-path probe as
// evidence: with no interface there is no client path, in the namespace or out of
// it, and the probe's failure is about the interface, not about where mihomo is.
func ClientInterfaceUp() bool { return wgiface.IsUp(ClientWGInterface) }

// syntheticPeer builds the master's own client peer for this spec, or the zero
// value when there is no key or the pool has no room for one. The address comes
// from the pool rather than from configuration so an operator resizing the pool
// moves the prober with it instead of stranding it outside.
func (p clientWGPlanner) syntheticPeer(cw domain.ClientWGSpec) domain.WGClient {
	if p.synthKey.PublicKey == "" {
		return domain.WGClient{}
	}
	addr, err := domain.SyntheticClientAddress(cw.AddressPool)
	if err != nil {
		// A pool too small to seat a prober still serves clients; it simply gets no
		// measurement. Refusing here would trade the thing for the thing that watches it.
		return domain.WGClient{}
	}
	return wg.SyntheticClient(addr, p.synthKey.PrivateKey, p.synthKey.PublicKey)
}

// peerDeltaActions brings the live peer list to the desired one with `awg set`,
// leaving the device — and every session on it — alone. nil means the difference
// cannot be applied that way and the caller must fall back to a bring-up.
//
// The conditions that are about INTERFACES live in wgiface.PeerDelta, which the
// exit's lifeline shares. The one condition that is about OWNERSHIP stays here:
// we may only patch an interface we have proof we raised. Without the claim this
// could be a wg0 someone else raised, whose interface parameters are theirs too,
// and patching its peers would leave the kernel serving the right people with the
// wrong obfuscation.
func (p clientWGPlanner) peerDeltaActions(want *domain.ClientWGSpec, prevCfg, newCfg string) []reconcile.Action {
	if !p.claimed() {
		return nil
	}
	return wgiface.PeerDelta(wgiface.Name(p.confPath), want.Clients, prevCfg, newCfg, p.ifacePeers)
}
