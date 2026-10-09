package master

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/netfw"
)

// legacyAWGPinTable is the table an operator added by hand on 2026-09-30 to pin
// one exit's AWG flow before this feature existed. Removed once the agent's own pin is
// armed, so the two never compete and nobody has to remember it.
const legacyAWGPinTable = "wgf_awg_pin"

// awgPinPlanner keeps conntrack consistent with the pinned address of every
// exit-initiated AWG tunnel.
//
// NAT is decided once per flow, on its first packet, so a pin rendered over a
// flow that already has an entry does nothing for it. Worse, after a mihomo
// restart the OLD entry keeps the pinned tuple: the exit's keepalives match its
// reply side and refresh it forever, the new socket's flow sits UNREPLIED beside
// it, and the tunnel never comes back on its own — observed on the live master
// 2026-09-30. This planner deletes such entries; the next packet from mihomo
// then starts one clean flow through the pin.
//
// It works from conntrack alone: reading mihomo's socket table would miss it
// entirely while mihomo runs in its own network namespace.
type awgPinPlanner struct {
	// list returns `conntrack -L` output for UDP to exitIP:port; nil ⇒ real exec.
	list func(ctx context.Context, exitIP string, port int) (string, error)
	// listKnocks returns `conntrack -L` output for UDP FROM exitIP:port — every
	// flow the exit opened towards the master, its knocks among them; nil ⇒ real
	// exec.
	listKnocks func(ctx context.Context, exitIP string, exitPort int) (string, error)
	// tableExists probes an nft table in family ip; nil ⇒ netfw.TableLoaded.
	tableExists func(name string) bool
	// heard reports whether the exit is in the gate's heard set; nil ⇒ nft.
	heard func(exitIP string) bool
	// sockets returns the local "ip:port" of every mihomo UDP socket to the exit,
	// read inside mihomo's own network namespace; ok=false when unreadable.
	// nil ⇒ docker + nsenter + ss.
	sockets func(ctx context.Context, exit string) (map[string]bool, bool)
}

func (awgPinPlanner) Component() string { return "exit-initiated AWG conntrack" }

// DependsOn: entries may only be cleared once the pin and the gate are in the
// kernel. Cleared before, mihomo's next packet leaves from a random port with
// nothing holding it back, and the master becomes the flow's initiator.
func (awgPinPlanner) DependsOn() string { return masterNATPlanner{}.Component() }

func (p awgPinPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	if spec.Master == nil {
		return nil, fmt.Errorf("exit-initiated AWG conntrack: node has no master spec")
	}
	pins := pinnedExits(spec)
	if len(pins) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("exit-initiated AWG conntrack", "no armed tunnel")}, nil
	}
	list, knocks, exists, heard := p.list, p.listKnocks, p.tableExists, p.heard
	if list == nil {
		list = listConntrackUDP
	}
	if knocks == nil {
		knocks = listConntrackKnocks
	}
	socks := p.sockets
	if socks == nil {
		socks = mihomoExitSockets
	}
	if exists == nil {
		exists = func(name string) bool { return netfw.TableLoaded("ip", name) }
	}
	if heard == nil {
		heard = exitHeard
	}

	var actions []reconcile.Action
	legacyRetired := false
	for _, pin := range pins {
		exit, err := netip.ParseAddrPort(pin.Exit)
		if err != nil {
			continue // the NAT renderer already refused it
		}
		master, err := netip.ParseAddrPort(pin.Master)
		if err != nil {
			continue
		}
		isHeard := heard(exit.Addr().String())
		actions = append(actions, exitOpenedFlowActions(ctx, knocks, pin.Exit, exit, int(master.Port()), isHeard)...)
		// Nothing else moves until the exit has knocked since the table was last
		// built. The set starts empty on every render, and a flow deleted before the
		// knock is a NEW flow the gate holds back until the next keepalive.
		if !isHeard {
			actions = append(actions, reconcile.NoChangeAction("exit-initiated AWG conntrack",
				"waiting for "+pin.Exit+" to knock on its pinned port"))
			continue
		}
		if !legacyRetired && exists(legacyAWGPinTable) {
			legacyRetired = true
			actions = append(actions, reconcile.BestEffortExecAction(
				"remove the hand-made pin table; the agent's own pin is armed",
				"nft", "delete", "table", "ip", legacyAWGPinTable))
		}
		out, err := list(ctx, exit.Addr().String(), int(exit.Port()))
		if err != nil {
			// Loud, not a quiet no-change: a tunnel stuck behind a stale entry is the
			// one case this planner exists for, and it would otherwise read as clean.
			slog.Warn("exit-initiated AWG: conntrack unreadable, stale entries cannot be cleared",
				"exit", pin.Exit, "err", err)
			actions = append(actions, reconcile.NoChangeAction("exit-initiated AWG conntrack",
				"conntrack unreadable for "+pin.Exit+": "+err.Error()))
			continue
		}
		entries := parseConntrackUDP(out)
		stale := staleAWGPinEntries(entries, int(master.Port()))
		if owned, ok := socks(ctx, pin.Exit); ok {
			stale = staleAWGPinEntriesOwned(entries, int(master.Port()), owned)
		}
		for _, e := range stale {
			actions = append(actions, reconcile.BestEffortExecAction(
				fmt.Sprintf("drop a conntrack entry that keeps %s off its pinned port", pin.Exit),
				"conntrack", "-D", "-p", "udp", "-s", e.origSrc, "-d", exit.Addr().String(),
				"--sport", strconv.Itoa(e.origSport), "--dport", strconv.Itoa(int(exit.Port()))))
		}
	}
	if len(actions) == 0 {
		return []reconcile.Action{reconcile.NoChangeAction("exit-initiated AWG conntrack", "every pinned flow is clean")}, nil
	}
	return actions, nil
}

// exitOpenedFlowActions deletes the conntrack entries of flows the exit opened
// towards the master from its AWG port. None of them is the pinned flow — that
// one the master opens, through the SNAT.
//
// On the pinned port it is a knock the master ACCEPTED (a whitelisted exit,
// before the gate was armed): a confirmed entry holding the tuple the SNAT
// needs, kept alive by every later knock even once dropped, so mihomo's writes
// fail NAT with EPERM for good. It goes once the exit is heard.
//
// On any other port it is the one mihomo used before the pin, which the exit's
// endpoint still named: mihomo's packets are replies of that entry and never
// meet the SNAT, so the tunnel lives off its pinned port with the gate reading
// armed. That one goes at once. Waiting for a knock would wait for good — the
// exit's endpoint roams back to the wrong port after every restore, so it
// hardly knocks at all (stand, kernel 5.15, 2026-10-09). Once the entry is gone
// the knock-drop rule refuses the exit's next packet there, its agent restores
// the endpoint, and the knock that follows opens the gate.
func exitOpenedFlowActions(ctx context.Context, list func(context.Context, string, int) (string, error),
	pinExit string, exit netip.AddrPort, pinnedPort int, heard bool) []reconcile.Action {
	out, err := list(ctx, exit.Addr().String(), int(exit.Port()))
	if err != nil {
		slog.Warn("exit-initiated AWG: conntrack unreadable, stale entries cannot be cleared",
			"exit", pinExit, "err", err)
		return nil
	}
	var actions []reconcile.Action
	for _, e := range parseConntrackUDP(out) {
		summary := fmt.Sprintf("drop a flow %s opened off its pinned port, which keeps the pin from applying", pinExit)
		if e.origDport == pinnedPort {
			if !heard {
				continue
			}
			summary = fmt.Sprintf("drop a confirmed knock from %s that holds its pinned tuple", pinExit)
		}
		actions = append(actions, reconcile.BestEffortExecAction(summary,
			"conntrack", "-D", "-p", "udp", "-s", e.origSrc, "-d", e.origDst,
			"--sport", strconv.Itoa(e.origSport), "--dport", strconv.Itoa(e.origDport)))
	}
	return actions
}

// ctEntry is the part of a UDP conntrack entry this planner decides on.
type ctEntry struct {
	origSrc    string
	origDst    string
	origSport  int
	origDport  int
	replyDport int
	unreplied  bool
}

// parseConntrackUDP reads `conntrack -L -p udp` lines: the first src/sport pair
// is the original direction, the second dport is the reply's destination port —
// the master's external port after NAT.
func parseConntrackUDP(out string) []ctEntry {
	var entries []ctEntry
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "udp") {
			continue
		}
		var e ctEntry
		var srcs, dsts, sports, dports []string
		for _, f := range strings.Fields(line) {
			k, v, ok := strings.Cut(f, "=")
			switch {
			case f == "[UNREPLIED]":
				e.unreplied = true
			case !ok:
			case k == "src":
				srcs = append(srcs, v)
			case k == "dst":
				dsts = append(dsts, v)
			case k == "sport":
				sports = append(sports, v)
			case k == "dport":
				dports = append(dports, v)
			}
		}
		if len(srcs) < 2 || len(dsts) < 2 || len(sports) < 2 || len(dports) < 2 {
			continue
		}
		e.origSrc, e.origDst = srcs[0], dsts[0]
		e.origSport, _ = strconv.Atoi(sports[0])
		e.origDport, _ = strconv.Atoi(dports[0])
		e.replyDport, _ = strconv.Atoi(dports[1])
		entries = append(entries, e)
	}
	return entries
}

// staleAWGPinEntries picks the entries to delete for one pinned tunnel:
//   - any flow NAT mapped to a port other than the pin (it predates the pin);
//   - when several flows hold the pin, every one but mihomo's single unanswered
//     attempt — or all of them when that attempt cannot be told apart.
func staleAWGPinEntries(entries []ctEntry, pinnedPort int) []ctEntry {
	var stale, onPin []ctEntry
	for _, e := range entries {
		if e.replyDport != pinnedPort {
			stale = append(stale, e)
			continue
		}
		onPin = append(onPin, e)
	}
	if len(onPin) <= 1 {
		return stale
	}
	waiting := 0
	for _, e := range onPin {
		if e.unreplied {
			waiting++
		}
	}
	for _, e := range onPin {
		if waiting == 1 && e.unreplied {
			continue
		}
		stale = append(stale, e)
	}
	return stale
}

func listConntrackUDP(ctx context.Context, exitIP string, port int) (string, error) {
	out, err := exec.CommandContext(ctx, "conntrack", "-L", "-p", "udp", "-d", exitIP,
		"--dport", strconv.Itoa(port)).Output()
	if err != nil {
		return "", fmt.Errorf("conntrack -L: %w", err)
	}
	return string(out), nil
}

// exitHeard asks the kernel whether the exit is in the gate's heard set.
func exitHeard(exitIP string) bool {
	return exec.Command("nft", "get", "element", "ip", netfw.MasterNATTable, netfw.AWGHeardSet,
		"{", exitIP, "}").Run() == nil
}

// exitOpenedFlowsArgs lists every UDP flow the exit opened from its AWG port,
// whatever port of the master it reached: the entry that breaks the pin is by
// definition not on the pinned one.
func exitOpenedFlowsArgs(exitIP string, exitPort int) []string {
	return []string{"-L", "-p", "udp", "-s", exitIP, "--sport", strconv.Itoa(exitPort)}
}

func listConntrackKnocks(ctx context.Context, exitIP string, exitPort int) (string, error) {
	out, err := exec.CommandContext(ctx, "conntrack", exitOpenedFlowsArgs(exitIP, exitPort)...).Output()
	if err != nil {
		return "", fmt.Errorf("conntrack -L: %w", err)
	}
	return string(out), nil
}

// staleAWGPinEntriesOwned is staleAWGPinEntries with the one fact conntrack alone
// cannot give: which entries a live mihomo socket still owns. On kernel 5.15 the
// new socket's flow never reaches conntrack after a restart — the NAT clash fails
// its insert — so the old entry is the only one listed, ASSURED, answered by the
// exit's keepalives, and owned by nobody. Found on the stand 2026-09-30.
func staleAWGPinEntriesOwned(entries []ctEntry, pinnedPort int, owned map[string]bool) []ctEntry {
	var stale []ctEntry
	for _, e := range entries {
		if e.replyDport != pinnedPort || !owned[net.JoinHostPort(e.origSrc, strconv.Itoa(e.origSport))] {
			stale = append(stale, e)
		}
	}
	return stale
}

// mihomoExitSockets reads mihomo's UDP sockets to exit inside mihomo's own
// network namespace (see mihomoUDPSockets).
func mihomoExitSockets(ctx context.Context, exit string) (map[string]bool, bool) {
	out, ok := mihomoUDPSockets(ctx)
	if !ok {
		return nil, false
	}
	var mine []string
	for line := range strings.SplitSeq(out, "\n") {
		if f := strings.Fields(line); len(f) >= 5 && f[4] == exit {
			mine = append(mine, line)
		}
	}
	return parseSSLocal(strings.Join(mine, "\n")), true
}

// parseSSLocal collects the local-address column of `ss -unaH` output.
func parseSSLocal(out string) map[string]bool {
	local := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 5 {
			local[f[3]] = true
		}
	}
	return local
}
