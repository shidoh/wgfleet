// Package rollout coordinates a fleet-wide rolling upgrade of exit-node agent
// binaries: one node at a time, reserve tier before primary, advancing only when
// the node it just touched has provably come back on the new build.
//
// It is deliberately separate from provmgr, which runs one node's job and knows
// nothing about fleet ordering, and from the web/CLI surfaces, which are two
// entry points into this one implementation.
package rollout

import (
	"sort"
	"strings"
	"time"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
)

// Tier is which exit tier a node belongs to (ADR-0029). Rollout order follows it.
type Tier string

const (
	// TierReserve carries no traffic while the primary tier is healthy.
	TierReserve Tier = "reserve"
	// TierPrimary carries live client traffic.
	TierPrimary Tier = "primary"
)

// Target is one node scheduled for upgrade.
type Target struct {
	NodeID  string
	Name    string
	Tier    Tier
	Current string // agent version reported before the upgrade ("" = never checked in)
}

// Skipped is a fleet exit excluded from the rollout, with the reason, so the
// dry-run shows the whole fleet accounted for rather than silently omitting nodes.
type Skipped struct {
	Name   string
	Reason string
}

// Plan is the ordered work a rollout would do.
type Plan struct {
	Targets []Target
	Skipped []Skipped
	// Want is the version the selection treated as current: the identity probed
	// from the agent binary this rollout would push. The per-node gate does NOT
	// use it — it uses the version probed from the binary that actually landed on
	// each node (see Coordinator.runNode) — but selecting on the same binary is
	// what keeps "outdated" meaning something a rollout can actually fix.
	Want string
	// Unavailable, when non-empty, is why no plan could be built — the agent
	// binary could not be identified, so "outdated" is unknowable. Rendering an
	// empty plan instead would read as "everything is up to date", which is a
	// different and false claim; callers surface this reason rather than offer a
	// roll they cannot describe.
	Unavailable string
}

// Outdated reports how many nodes the plan would touch.
func (p Plan) Outdated() int { return len(p.Targets) }

// BuildPlan orders a rolling upgrade over the fleet's exits.
//
// Masters are excluded unconditionally and by construction — this walks
// fleet.Exits and never fleet.Masters. The master is co-located with the
// controller (the documented default deployment), so restarting its agent would
// restart the process running the rollout and abandon it mid-flight. A master is
// upgraded on its own, via deploy-master.sh or the per-node action.
//
// Reserve exits go first: a bad binary should be discovered on a node carrying no
// client traffic, where the blast radius of a crash-looping agent is zero. Within
// a tier the order is by name, so a plan is reproducible and an operator reading
// a dry-run knows exactly which node is next.
// FreshWithinFor derives the staleness bound from the fleet's own reconcile
// cadence. A fixed bound cannot work: reconcile_interval is operator-configurable
// (up to an hour), so a node set to report every five minutes is ALWAYS stale
// against a 90-second window — and would be silently dropped from every fleet-wide
// rollout while being perfectly healthy and reporting exactly on schedule. Two
// intervals gives a node room to miss one report without being written off, with
// the fixed default as a floor for fast cadences.
func FreshWithinFor(fleet config.FleetSection) time.Duration {
	if d := 2 * fleet.AgentReconcileInterval(); d > DefaultFreshWithin {
		return d
	}
	return DefaultFreshWithin
}

// now and freshWithin decide which nodes are up enough to be worth touching. A node
// that is already down is not a candidate: pushing to it burns the come-back gate's
// full timeout, ROLLS THE NODE BACK, and halts the rollout at that point — and since
// reserve sorts first, one dead reserve node blocked every primary behind it while
// the dry-run listed it as an ordinary target.
func BuildPlan(fleet config.FleetSection, nodes []domain.Node, want string, now time.Time, freshWithin time.Duration) Plan {
	reserve := reserveSet(fleet)
	byID := make(map[string]domain.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	plan := Plan{Want: want}
	for _, e := range fleet.Exits {
		n, known := byID[e.Name]
		switch {
		case e.SSH.Host == "" || e.SSH.KeyPath == "":
			// The upgrade channel is SSH; without a target we cannot push a binary or
			// roll one back, and a node we cannot recover must not be started.
			plan.Skipped = append(plan.Skipped, Skipped{e.Name, "no ssh target in the manifest"})
			continue
		case known && n.AgentVersion == want && want != "":
			plan.Skipped = append(plan.Skipped, Skipped{e.Name, "already on " + want})
			continue
		case !known:
			plan.Skipped = append(plan.Skipped, Skipped{e.Name, "has never reported to the controller"})
			continue
		// Staleness is the ONLY health signal used here, deliberately. What decides
		// whether an upgrade can succeed is whether the node checks in after its
		// restart, and LastSeen measures exactly that. Skipping on State would also
		// skip a Degraded node — including one that is degraded BECAUSE of the bug
		// being rolled out, which is the node the operator most needs to reach.
		case n.LastSeen.IsZero() || now.Sub(n.LastSeen) > freshWithin:
			plan.Skipped = append(plan.Skipped, Skipped{e.Name,
				"has not reported for " + now.Sub(n.LastSeen).Round(time.Second).String()})
			continue
		}
		t := Target{NodeID: e.Name, Name: e.Name, Tier: TierPrimary, Current: n.AgentVersion}
		if reserve[e.Name] {
			t.Tier = TierReserve
		}
		plan.Targets = append(plan.Targets, t)
	}

	sort.SliceStable(plan.Targets, func(i, j int) bool {
		a, b := plan.Targets[i], plan.Targets[j]
		if a.Tier != b.Tier {
			return a.Tier == TierReserve
		}
		return a.Name < b.Name
	})
	return plan
}

// reserveSet is the union of every master's reserve_exits. Union, not per-master:
// an exit that is reserve for one master and primary for another still carries
// traffic, so treating it as reserve would defeat the ordering's purpose — but
// with a single master (the only shipped topology) the union is exact.
func reserveSet(fleet config.FleetSection) map[string]bool {
	out := map[string]bool{}
	for _, m := range fleet.Masters {
		for _, name := range m.Routing.ReserveExits {
			if name = strings.TrimSpace(name); name != "" {
				out[name] = true
			}
		}
	}
	return out
}
