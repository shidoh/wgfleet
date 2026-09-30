package master

import (
	"context"
	"fmt"
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
	// tableExists probes an nft table in family ip; nil ⇒ netfw.TableLoaded.
	tableExists func(name string) bool
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
	list, exists := p.list, p.tableExists
	if list == nil {
		list = listConntrackUDP
	}
	if exists == nil {
		exists = func(name string) bool { return netfw.TableLoaded("ip", name) }
	}

	var actions []reconcile.Action
	if exists(legacyAWGPinTable) {
		actions = append(actions, reconcile.BestEffortExecAction(
			"remove the hand-made pin table; the agent's own pin is armed",
			"nft", "delete", "table", "ip", legacyAWGPinTable))
	}
	for _, pin := range pins {
		exit, err := netip.ParseAddrPort(pin.Exit)
		if err != nil {
			continue // the NAT renderer already refused it
		}
		master, err := netip.ParseAddrPort(pin.Master)
		if err != nil {
			continue
		}
		out, err := list(ctx, exit.Addr().String(), int(exit.Port()))
		if err != nil {
			actions = append(actions, reconcile.NoChangeAction("exit-initiated AWG conntrack",
				"conntrack unreadable for "+pin.Exit+": "+err.Error()))
			continue
		}
		for _, e := range staleAWGPinEntries(parseConntrackUDP(out), int(master.Port())) {
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

// ctEntry is the part of a UDP conntrack entry this planner decides on.
type ctEntry struct {
	origSrc    string
	origSport  int
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
		var srcs, sports, dports []string
		for _, f := range strings.Fields(line) {
			k, v, ok := strings.Cut(f, "=")
			switch {
			case f == "[UNREPLIED]":
				e.unreplied = true
			case !ok:
			case k == "src":
				srcs = append(srcs, v)
			case k == "sport":
				sports = append(sports, v)
			case k == "dport":
				dports = append(dports, v)
			}
		}
		if len(srcs) < 2 || len(sports) < 2 || len(dports) < 2 {
			continue
		}
		e.origSrc = srcs[0]
		e.origSport, _ = strconv.Atoi(sports[0])
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
