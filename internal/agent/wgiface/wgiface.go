// Package wgiface holds the interface-management helpers shared by the two
// client-facing AmneziaWG interfaces the fleet raises: the master's (the leg
// that used to be wg-easy's) and the exit's lifeline.
//
// They were extracted from the master's client_wg planner rather than written
// fresh, and deliberately so: that planner carries the most sensitive interface
// on the fleet, and every rule in here — read peers with `show`, never `dump`;
// patch peers instead of bouncing the device when the [Interface] section held
// still; add and remove peers rather than destroying every session over one
// credential — was paid for by a live outage. A second interface reasoning
// about the same questions must reach the same answers, which it can only do by
// running the same code.
package wgiface

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// Name derives the interface name from the config path, the way awg-quick does.
func Name(path string) string {
	return strings.TrimSuffix(filepath.Base(path), ".conf")
}

// Peers lists the live interface's peer public keys. `awg show <iface> peers` is
// used rather than `dump` deliberately: dump's first line carries the interface
// PRIVATE key, and a command whose output might be logged should not have it in
// hand.
func Peers(name string) ([]string, error) {
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

// IsUp reports whether an interface exists (awg-quick creates it on `up`).
func IsUp(name string) bool {
	return exec.Command("ip", "link", "show", name).Run() == nil
}

// UserspaceImplementation is the daemon awg-quick runs when the userspace backend
// is selected. awg-quick reads it from the environment, which is why the userspace
// path goes through `sh -c` — the plan then shows the operator the exact command,
// environment included, that they could paste into a shell themselves.
//
// Exported because a caller that OFFERS the userspace backend has to check the
// daemon is actually installed before rendering a config that depends on it, and
// it must look for the same binary awg-quick will.
const UserspaceImplementation = "amneziawg-go"

// QuickAction builds one awg-quick invocation for the selected backend.
func QuickAction(backend domain.ClientWGBackend, verb, confPath string, bestEffort bool, summary string) reconcile.Action {
	cmd := []string{"awg-quick", verb, confPath}
	if backend == domain.ClientWGBackendUserspace {
		cmd = []string{"sh", "-c", fmt.Sprintf("WG_QUICK_USERSPACE_IMPLEMENTATION=%s awg-quick %s %s",
			UserspaceImplementation, verb, shQuote(confPath))}
	}
	if bestEffort {
		return reconcile.BestEffortExecAction(summary, cmd...)
	}
	return reconcile.ExecAction(summary, cmd...)
}

// shQuote single-quotes a path for safe interpolation into an `sh -c` command.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// reader resolves the live peer reader, defaulting to the real `awg show`.
func reader(live func(string) ([]string, error)) func(string) ([]string, error) {
	if live == nil {
		return Peers
	}
	return live
}

// ServesPeers reports whether the live interface carries exactly the peers the
// spec asks for. A mismatch means somebody else configured it (a wg-easy
// container that survived a reboot) or our own apply half-failed; either way the
// answer is to re-apply.
//
// A probe that fails answers TRUE — "assume it matches". The alternative would
// bounce a healthy interface on every pass on any node where the probe cannot run,
// which is a worse failure than missing a takeover we will also catch the next
// time the config changes.
//
// The second return says whether it could be asked at all, and it matters: a probe
// that cannot run must not be read as "matches" by a caller about to delete the
// only fallback, even though it is correctly read that way by the caller deciding
// whether to re-apply (where failing open avoids a pointless interface bounce).
func ServesPeers(iface string, want []domain.WGClientPeer, live func(string) ([]string, error)) (matches, known bool) {
	livePeers, err := reader(live)(iface)
	if err != nil {
		return true, false
	}
	wanted := make(map[string]struct{}, len(want))
	for _, c := range want {
		wanted[c.PublicKey] = struct{}{}
	}
	if len(livePeers) != len(wanted) {
		return false, true
	}
	for _, key := range livePeers {
		if _, ok := wanted[key]; !ok {
			return false, true
		}
	}
	return true, true
}

// PeerDelta brings the live peer list to the desired one with `awg set`, leaving
// the device — and every session on it — alone. nil means the difference cannot be
// applied that way and the caller must fall back to a bring-up.
//
// Two conditions, and each is a real limit rather than caution:
//
//   - The [Interface] section must be unchanged. Addresses, the listen port, the
//     MTU and the AmneziaWG obfuscation parameters are fixed when the device is
//     created; `awg set` cannot move them, and pretending otherwise would leave the
//     kernel running one configuration while the file on disk claims another.
//   - The live peer list must be readable, and must share at least one peer with
//     the desired one whenever it holds peers we no longer want.
//
// That second condition is what is left of an older, much stricter one: the live
// list had to be a SUBSET of the desired one, so a single revoked credential sent
// the whole device through down/up and dropped every other session with it. What
// the strict version was really guarding against is a peer list that is not ours
// at all — a wg-easy container that recreated wg0 after a reboot, whose INTERFACE
// parameters are wg-easy's too and which `awg set` cannot correct. An entirely
// disjoint live list still means exactly that and still rebuilds the device; a
// list that overlaps ours is ours, with somebody removed from it.
//
// Any further condition the CALLER owns — the master, for instance, also requires
// the claim that proves it raised this interface — belongs before the call, not in
// here: this package knows about interfaces, not about who owns them.
func PeerDelta(iface string, want []domain.WGClientPeer, prevCfg, newCfg string, live func(string) ([]string, error)) []reconcile.Action {
	if prevCfg == "" || wg.InterfaceSection(prevCfg) != wg.InterfaceSection(newCfg) {
		return nil
	}
	livePeers, err := reader(live)(iface)
	if err != nil {
		return nil
	}
	have := make(map[string]bool, len(livePeers))
	for _, k := range livePeers {
		have[k] = true
	}

	var actions []reconcile.Action
	wanted := map[string]bool{}
	overlap := 0
	for _, c := range want {
		if c.PublicKey == "" {
			continue
		}
		wanted[c.PublicKey] = true
		if have[c.PublicKey] {
			overlap++
			continue
		}
		if c.Address == "" {
			return nil
		}
		actions = append(actions, peerSetAction(iface, c))
	}
	// A live peer that is no longer issued is REMOVED, not a reason to rebuild.
	//
	// It used to be one, and the cost was out of all proportion: `awg-quick down/up`
	// destroys every session on the device, so pausing or revoking ONE credential
	// dropped everybody — on the lifeline, everybody who is there precisely because
	// their normal path is already gone. The check it replaced was guarding against
	// a DIFFERENT interface (wg-easy's wg0, whose peers are not ours to edit), and
	// two conditions already prove that cannot be the case here: the previously
	// rendered [Interface] section has to match the one we are about to write, and
	// the master additionally requires its claim before it calls this at all.
	//
	// The one thing still worth refusing is a live peer list with NOTHING in common
	// with the wanted one on an interface that has peers: an entirely foreign set is
	// better rebuilt than silently emptied one `awg set … remove` at a time.
	var removals []reconcile.Action
	for key := range have {
		if !wanted[key] {
			removals = append(removals, reconcile.ExecAction(
				"remove peer "+shortKey(key)+" (no longer issued) without disturbing the interface",
				"awg", "set", iface, "peer", key, "remove"))
		}
	}
	if len(removals) > 0 && overlap == 0 {
		return nil
	}
	actions = append(actions, removals...)
	if len(actions) == 0 {
		return nil
	}
	return actions
}

// peerSetAction adds or updates ONE peer with `awg set`, leaving the device — and
// every session on it — alone.
//
// A preshared key is handed over a 0600 temp file rather than on the command
// line, which is what `awg`'s own `preshared-key <file>` argument is for: the
// alternative used to be refusing the patch outright, and since every credential
// the controller issues carries a derived preshared key (ADR-0034), that refusal
// meant the patch path was never taken in production — adding one client bounced
// the interface and dropped all the others. The file lives only for the duration
// of the call, and the plan's Display never shows the secret.
func peerSetAction(iface string, c domain.WGClientPeer) reconcile.Action {
	allowed := hostPrefix(c.Address)
	summary := "add peer " + c.Name + " without disturbing the interface"
	if c.PresharedKey == "" {
		return reconcile.ExecAction(summary, "awg", "set", iface, "peer", c.PublicKey, "allowed-ips", allowed)
	}
	display := strings.Join([]string{
		"awg", "set", iface, "peer", c.PublicKey, "preshared-key", "<file>", "allowed-ips", allowed,
	}, " ")
	psk := c.PresharedKey
	return reconcile.CustomAction(reconcile.ActionExec, "awg", summary, display, func(ctx context.Context) error {
		f, err := os.CreateTemp("", "wgfleet-psk-")
		if err != nil {
			return fmt.Errorf("preshared key for peer %s: %w", shortKey(c.PublicKey), err)
		}
		defer os.Remove(f.Name())
		if _, err := f.WriteString(psk + "\n"); err != nil {
			f.Close()
			return fmt.Errorf("preshared key for peer %s: %w", shortKey(c.PublicKey), err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("preshared key for peer %s: %w", shortKey(c.PublicKey), err)
		}
		cmd := exec.CommandContext(ctx, "awg", "set", iface,
			"peer", c.PublicKey, "preshared-key", f.Name(), "allowed-ips", allowed)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", display, err, strings.TrimSpace(string(out)))
		}
		return nil
	})
}

// shortKey names a peer in a summary without printing the whole public key. The
// key is not a secret, but a plan line is read by a person and 44 base64
// characters are not what makes it legible.
func shortKey(pub string) string {
	if len(pub) <= 8 {
		return pub
	}
	return pub[:8] + "…"
}

// hostPrefix turns a client address into the single-host prefix the server side
// allows for it. An address that already carries a prefix is used as written.
func hostPrefix(addr string) string {
	if strings.Contains(addr, "/") {
		return addr
	}
	return addr + "/32"
}

// --- deferral markers ---

// DeferredSuffix is appended to an interface config path to locate the file where
// a planner records WHY it is not applying the spec.
const DeferredSuffix = ".deferred"

// DeferredPath returns the deferral marker for an interface config. Exported so
// the health probes read exactly the path the planners write — the suffix has one
// owner, and a check that looked at the wrong file would report green through
// precisely the states the marker exists to surface.
func DeferredPath(confPath string) string { return confPath + DeferredSuffix }

// Deferral is a planner's record of a pass it declined to apply.
//
// It exists because a health check that reads the WORLD cannot see a DECISION:
// an interface that is up stays up through "no key yet", "spec rejected" and
// "AmneziaWG 3.x refused", so every one of those reported green — including a
// malformed credential freezing the interface while later revocations silently
// stop taking effect. The marker is the planner's verdict, written where the
// check can find it.
type Deferral struct {
	// Path is the marker file, normally DeferredPath(confPath).
	Path string
	// Component names the planner in the plan output's no-change line.
	Component string
}

// Write returns the plan for a pass that declines to apply: record the reason,
// and say so in the plan.
func (d Deferral) Write(reason string) []reconcile.Action {
	act, err := reconcile.FileAction(d.Path, []byte(reason+"\n"), 0o600, nil)
	if err != nil {
		// Recording the reason is diagnostics; failing the pass over it would be the
		// freeze the deferral exists to avoid.
		return []reconcile.Action{reconcile.NoChangeAction(d.Component, reason)}
	}
	return []reconcile.Action{act, reconcile.NoChangeAction(d.Component, reason)}
}

// Arm records the marker for a pass that is about to TRY, without the plan line
// Write adds — this is not a pass that declined to do anything.
//
// It exists because the two awg-quick steps that follow are best-effort: neither
// aborts the pass, so a bounce that fails leaves the interface up on its previous
// config with a peer list that is no longer the spec's, and nothing else on the
// node notices. Armed here and cleared by the bring-up itself (ClearedBy), the
// marker survives exactly that case and the health check reports it.
func (d Deferral) Arm(reason string) reconcile.Action {
	act, err := reconcile.FileAction(d.Path, []byte(reason+"\n"), 0o600, nil)
	if err != nil {
		return reconcile.NoChangeAction(d.Component, "could not record the deferral at "+d.Path+": "+err.Error())
	}
	return act
}

// ClearedBy removes the marker when a — and only when a — actually succeeds.
//
// Compose order matters: the hook goes on before any BestEffort wrapper, so it
// fires on a real success rather than on the wrapper's unconditional one.
func (d Deferral) ClearedBy(a reconcile.Action) reconcile.Action {
	path := d.Path
	return a.OnApplied(func() { _ = os.Remove(path) })
}

// Clear removes the marker once the planner is applying or converged.
func (d Deferral) Clear() reconcile.Action {
	act, err := reconcile.RemoveFileAction(d.Path, "clear the deferral for "+d.Component)
	if err != nil {
		return reconcile.NoChangeAction(d.Component, "could not clear the deferral at "+d.Path+": "+err.Error())
	}
	return act
}
