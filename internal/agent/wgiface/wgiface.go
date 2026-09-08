// Package wgiface holds the interface-management helpers shared by the two
// client-facing AmneziaWG interfaces the fleet raises: the master's (the leg
// that used to be wg-easy's) and the exit's lifeline.
//
// They were extracted from the master's client_wg planner rather than written
// fresh, and deliberately so: that planner carries the most sensitive interface
// on the fleet, and every rule in here — read peers with `show`, never `dump`;
// patch peers instead of bouncing the device when the [Interface] section held
// still; refuse the patch the moment the live peer list stops being a subset of
// the wanted one — was paid for by a live outage. A second interface reasoning
// about the same questions must reach the same answers, which it can only do by
// running the same code.
package wgiface

import (
	"fmt"
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
// Three conditions, and each is a real limit rather than caution:
//
//   - The [Interface] section must be unchanged. Addresses, the listen port, the
//     MTU and the AmneziaWG obfuscation parameters are fixed when the device is
//     created; `awg set` cannot move them, and pretending otherwise would leave the
//     kernel running one configuration while the file on disk claims another.
//   - No peer being ADDED may carry a preshared key. `awg set` reads one from a
//     FILE, and the alternatives — a path we would have to create and delete, or
//     the key on a command line — are worse than a re-handshake.
//   - The live peer list must be readable and must be a SUBSET of the desired one.
//
// The subset condition is what makes this safe rather than merely cheap. A live
// interface carrying a peer we do not want is not an interface missing an entry —
// it is somebody else's peer list, which is how a wg-easy container that recreated
// wg0 after a reboot presents itself. Its INTERFACE parameters are wg-easy's too,
// and `awg set` cannot correct those, so patching peers would leave the kernel
// serving the right people with the wrong obfuscation. That case still recreates
// the device, which is the only thing that fixes it.
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
	for _, c := range want {
		if c.PublicKey == "" {
			continue
		}
		wanted[c.PublicKey] = true
		if have[c.PublicKey] {
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
	for key := range have {
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

// Clear removes the marker once the planner is applying or converged.
func (d Deferral) Clear() reconcile.Action {
	act, err := reconcile.RemoveFileAction(d.Path, "clear the deferral for "+d.Component)
	if err != nil {
		return reconcile.NoChangeAction(d.Component, "could not clear the deferral at "+d.Path+": "+err.Error())
	}
	return act
}
