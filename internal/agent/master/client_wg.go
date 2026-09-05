package master

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

	// The question is NOT "whose interface is this" — after key adoption that has no
	// answer — but "does the live interface serve what the spec says". That covers
	// every case the ownership question was meant to: a wg-easy container that
	// recreated wg0 carries wg-easy's peer list, which will not match ours, so we
	// re-apply and take it over.
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
	// block remains a different instruction — "release the leg" — handled above.
	// Removing every live peer is still worth a line in the journal, so it is
	// summarised rather than silent.
	if live, known := p.livePeerCount(); known && live > 0 && len(cw.Clients) == 0 {
		actions = append(actions, reconcile.NoChangeAction("client AmneziaWG interface",
			fmt.Sprintf("the spec has no clients: removing all %d live peer(s)", live)))
	}

	// Past every deferral: whatever the last pass declined to do, it is doing it now.
	actions = append(actions, p.clearDeferred())

	peersMatch, peersKnown := p.servesDesiredPeers(&rendered)
	// Before deciding to recreate the device: can this be done as a peer edit?
	//
	// `awg-quick down` + `up` destroys the interface, and with it every established
	// session on it — all seven devices on the live master lose their tunnel and
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

	// Converged. Whether we may retire the fallback now turns on ONE question: is
	// there proof that WE raised this interface? After key adoption identity cannot
	// answer it — our public key and wg-easy's are the same value by design — so the
	// proof is the claim, written by a bring-up that actually succeeded.
	if claim.Changes() {
		// No claim. An interface that is up and serving the right peers is exactly as
		// consistent with wg-easy still carrying it... unless wg-easy is not installed
		// at all, in which case nothing else could have raised it. That second case is
		// the upgrade path from a build predating the claim, and it is safe to record.
		if p.wgEasyPresent() {
			return append(actions, reconcile.NoChangeAction("client AmneziaWG interface",
				"interface already up, but ownership is unproven while wg-easy is still installed")), nil
		}
		return append(actions, claim,
			reconcile.NoChangeAction("client AmneziaWG interface", "interface already up")), nil
	}

	// A claim from an earlier pass: an awg-quick up succeeded and the interface is
	// still up and still serving our peers. Only now is the fallback spare.
	//
	// peersKnown is required as well. The peer probe fails OPEN — an unanswerable
	// `awg show` reports "matches" so a broken probe cannot bounce a healthy
	// interface — and that is the right trade for deciding whether to re-apply. It
	// is the wrong trade for deciding whether to delete the only fallback.
	if p.wgEasyPresent() && peersKnown {
		actions = append(actions, reconcile.BestEffortExecAction(
			"retire the wg-easy container (the agent is carrying the client interface)",
			"docker", "rm", "-f", wgEasyContainer))
	}
	return append(actions, reconcile.NoChangeAction("client AmneziaWG interface", "interface already up")), nil
}

// applyActions brings the interface to the rendered config. Both steps are
// best-effort ON PURPOSE: this planner runs early (it must release the interface
// before the compose planner can restore wg-easy), and the reconcile engine stops
// the whole pass at the first failed action. A client interface that will not come
// up must not also freeze mihomo, the master NAT, DOCKER-USER, blocky and the
// VLESS inbound. The failure is visible as a warning and as the client-wg health
// check going red, and the next pass retries.
func (p clientWGPlanner) applyActions(backend domain.ClientWGBackend, why string) []reconcile.Action {
	// The claim is a RECEIPT for a successful bring-up, not a record that one was
	// attempted. It used to be appended to the plan unconditionally, so a failed
	// `awg-quick up` still produced a claim — and two later decisions read that
	// claim as proof the agent carries the interface: retiring wg-easy, and the
	// client-wg-owned health check. Both were reading evidence that did not
	// establish the fact.
	//
	// OnApplied fires only when the exec really succeeded; BestEffort then keeps a
	// failure from aborting the pass, which is why the order matters.
	up := quickAction(backend, "up", p.confPath, false, "bring the client interface up: "+why).
		OnApplied(p.recordClaim).
		BestEffort()
	return []reconcile.Action{
		quickAction(backend, "down", p.confPath, true, "bring the client interface down (if up): "+why),
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
		read = interfacePeers
	}
	live, err := read(clientIfaceName(p.confPath))
	if err != nil {
		return 0, false
	}
	return len(live), true
}

// deferredPath is where the planner records WHY it is not applying the spec.
//
// It exists because the client-wg-owned health check could not see a deferral at
// all: it probes the claim file and `ip link show`, and after a successful
// handover both stay true forever. So "no key yet", "spec rejected" and "3.x
// refused" all reported green — including the case where a single malformed
// credential freezes the interface and every later revocation silently stops
// taking effect while the UI reports success. A check that reads the world cannot
// see a decision the planner made; it has to read the planner's verdict.
func (p clientWGPlanner) deferredPath() string { return p.confPath + ".deferred" }

// deferred returns the plan for a pass that declines to apply, recording the
// reason where the health check can find it.
func (p clientWGPlanner) deferred(reason string) []reconcile.Action {
	act, err := reconcile.FileAction(p.deferredPath(), []byte(reason+"\n"), 0o600, nil)
	if err != nil {
		// Recording the reason is diagnostics; failing the pass over it would be the
		// freeze this whole branch exists to avoid.
		return []reconcile.Action{reconcile.NoChangeAction("client AmneziaWG interface", reason)}
	}
	return []reconcile.Action{act, reconcile.NoChangeAction("client AmneziaWG interface", reason)}
}

// clearDeferred removes the marker once the planner is applying or converged.
func (p clientWGPlanner) clearDeferred() reconcile.Action {
	act, err := reconcile.RemoveFileAction(p.deferredPath(), "clear the client interface deferral")
	if err != nil {
		return reconcile.NoChangeAction("client AmneziaWG interface", "")
	}
	return act
}

// recordClaim writes the claim file. Best-effort by design: failing to record it
// costs a redundant re-apply next pass, whereas failing the pass here would take
// the master's other subsystems down with it.
func (p clientWGPlanner) recordClaim() {
	if err := os.WriteFile(p.claimPath(), []byte(claimContents), 0o600); err != nil {
		slog.Warn("could not record the client interface claim", "path", p.claimPath(), "err", err)
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
// servesDesiredPeers reports whether the live interface serves exactly the spec's
// peers, and whether it could be asked at all. The second return matters: a probe
// that cannot run must not be read as "matches" by a caller about to delete the
// only fallback, even though it is correctly read that way by the caller deciding
// whether to re-apply (where failing open avoids a pointless interface bounce).
func (p clientWGPlanner) servesDesiredPeers(cw *domain.ClientWGSpec) (matches, known bool) {
	read := p.ifacePeers
	if read == nil {
		read = interfacePeers
	}
	live, err := read(clientIfaceName(p.confPath))
	if err != nil {
		return true, false
	}
	want := make(map[string]struct{}, len(cw.Clients))
	for _, c := range cw.Clients {
		want[c.PublicKey] = struct{}{}
	}
	if len(live) != len(want) {
		return false, true
	}
	for _, key := range live {
		if _, ok := want[key]; !ok {
			return false, true
		}
	}
	return true, true
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

// InterfacePublicKey asks the live interface for its own public key.
//
// This is the durable half of the client-identity audit. Comparing against
// wg-easy's database only works while that database is still on disk, which after
// the handover it need not be; the interface itself is there for as long as
// clients are being served, so "the key I publish" can always be checked against
// "the key actually answering handshakes".
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

// clientIfaceName derives the interface name from the config path, the way
// awg-quick does.
func clientIfaceName(path string) string {
	return strings.TrimSuffix(filepath.Base(path), ".conf")
}

// ipLinkUp reports whether an interface exists (awg-quick creates it on `up`).
func ipLinkUp(name string) bool {
	return exec.Command("ip", "link", "show", name).Run() == nil
}

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
// Three conditions, and each is a real limit rather than caution:
//
//   - The [Interface] section must be unchanged. Addresses, the listen port, the
//     MTU and the AmneziaWG obfuscation parameters are fixed when the device is
//     created; `awg set` cannot move them, and pretending otherwise would leave the
//     kernel running one configuration while the file on disk claims another.
//   - No peer being ADDED may carry a preshared key. `awg set` reads one from a
//     FILE, and the alternatives — a path we would have to create and delete, or
//     the key on a command line — are worse than a re-handshake.
//   - The live peer list must be readable, must be a SUBSET of the desired one,
//     and we must hold the claim.
//
// The subset condition is what makes this safe rather than merely cheap. A live
// interface carrying a peer we do not want is not an interface missing an entry —
// it is somebody else's peer list, which is how a wg-easy container that recreated
// wg0 after a reboot presents itself. Its INTERFACE parameters are wg-easy's too,
// and `awg set` cannot correct those, so patching peers would leave the kernel
// serving the right people with the wrong obfuscation. That case still recreates
// the device, which is the only thing that fixes it.
func (p clientWGPlanner) peerDeltaActions(want *domain.ClientWGSpec, prevCfg, newCfg string) []reconcile.Action {
	if prevCfg == "" || wg.InterfaceSection(prevCfg) != wg.InterfaceSection(newCfg) {
		return nil
	}
	if !p.claimed() {
		return nil
	}
	read := p.ifacePeers
	if read == nil {
		read = interfacePeers
	}
	iface := clientIfaceName(p.confPath)
	livePeers, err := read(iface)
	if err != nil {
		return nil
	}
	live := make(map[string]bool, len(livePeers))
	for _, k := range livePeers {
		live[k] = true
	}

	var actions []reconcile.Action
	wanted := map[string]bool{}
	for _, c := range want.Clients {
		if c.PublicKey == "" {
			continue
		}
		wanted[c.PublicKey] = true
		if live[c.PublicKey] {
			continue
		}
		if c.PresharedKey != "" {
			return nil // cannot hand a secret to `awg set` without writing it somewhere
		}
		if c.Address == "" {
			return nil
		}
		actions = append(actions, reconcile.ExecAction(
			"add peer "+c.Name+" without disturbing the interface",
			"awg", "set", iface, "peer", c.PublicKey, "allowed-ips", hostPrefix(c.Address)))
	}
	for key := range live {
		if !wanted[key] {
			return nil // not our peer list; only a rebuild puts this interface right
		}
	}
	if len(actions) == 0 {
		return nil
	}
	return actions
}

// hostPrefix turns a client address into the single-host prefix the server side
// allows for it. An address that already carries a prefix is used as written.
func hostPrefix(addr string) string {
	if strings.Contains(addr, "/") {
		return addr
	}
	return addr + "/32"
}
