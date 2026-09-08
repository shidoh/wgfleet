// Package routing renders the policy-routing intent (RoutingSpec) into a
// deterministic, idempotent sequence of shell steps (ip rule/route, sysctl,
// conntrack, nft mangle). It encodes the hard-won routing lessons directly
// (docs/DESIGN.md #2–#5, #9) so the platform cannot reintroduce the failures we hit
// by hand. Steps are returned as data; the reconcile layer wraps them as exec
// actions, so dry-run shows the exact commands without running them.
package routing

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// EgressTable is the routing table id that carries client traffic toward the
// egress interface. Kept off the main table so management/handshake traffic
// (which stays in main) is never pulled into WARP. Exported because the
// live-kernel drift probe queries `ip route show table <EgressTable>` to verify
// the intent is still applied.
const EgressTable = 51820

// fwmarkClient is the default fwmark for WG handshake/reply packets when the spec
// does not set one. Marking is done by source port in nftables mangle, not by
// CONNMARK — CONNMARK picked up stray marks from conntrack. The nft
// mangle rule that actually SETS this mark is rendered by internal/netfw (it owns
// the node's nft ruleset and knows the WG port); this package only adds the
// matching `ip rule fwmark <mark> lookup main` so the two must agree on the value.
const fwmarkClient = 0x1

// EffectiveFwMark returns the fwmark a node uses to keep WG handshake/reply
// traffic on the main table: the spec's value, or the default. Both the routing
// ip-rule (here) and the nft mangle rule (netfw) resolve it through this, so the
// mark that is SET matches the mark that is matched.
func EffectiveFwMark(r domain.RoutingSpec) int {
	if r.FwMark != 0 {
		return r.FwMark
	}
	return fwmarkClient
}

// ip-rule priorities. Each logical rule owns a fixed priority so it can be
// replaced by a delete-by-pref then add: deleting by priority clears whatever
// selector currently sits there (e.g. a stale master IP after the spec changed),
// so re-applying never leaves a duplicate or an orphan.
const (
	prefMaster        = 100 // keep master-bound traffic on the main table
	prefDirect0       = 110 // first direct-CIDR rule; CIDR i uses prefDirect0+i
	prefFwmark        = 200 // keep WG replies/handshake (fwmark) on the main table
	prefEgress        = 300 // send client traffic (from ClientCIDR) to the egress table
	prefLifeline      = 305 // send lifeline client traffic (from LifelineCIDR) to the egress table
	prefRealityEgress = 310 // send reality-marked host traffic to the egress table (ADR-0025)
)

// MaxDirectCIDRs caps the number of direct-CIDR rules. Each consumes priority
// prefDirect0+i, so without a cap a large list would walk into prefFwmark (200)
// and silently overwrite the fwmark rule that keeps WG handshake/reply traffic on
// the main table — reintroducing an earlier finding (clients see a Cloudflare source and
// drop, the master loses peers). The cap leaves a margin below prefFwmark.
const MaxDirectCIDRs = prefFwmark - prefDirect0 - 10 // 80

// Step is one idempotent routing command. BestEffort marks a step whose failure
// must be tolerated (e.g. `ip rule del` of a rule that does not exist yet): the
// reconcile layer wraps it so it never aborts the pass.
type Step struct {
	Summary    string
	Argv       []string
	BestEffort bool
}

// Render produces the ordered routing steps for spec on an exit node. The order
// matters: relax rp_filter and flush conntrack first, then install rules, then
// the egress default route last.
func Render(spec domain.RoutingSpec) ([]Step, error) {
	if spec.EgressInterface == "" {
		// No egress interface ⇒ direct egress; nothing to policy-route.
		return nil, nil
	}
	if n := len(spec.DirectCIDRs); n > MaxDirectCIDRs {
		// Defense in depth: config.Validate rejects this earlier, but never render a
		// rule set whose priorities would collide with the fwmark rule.
		return nil, fmt.Errorf("routing: %d direct CIDRs exceeds the max of %d (would collide with the fwmark rule)", n, MaxDirectCIDRs)
	}
	mark := EffectiveFwMark(spec)

	var steps []Step

	// an earlier finding: packets arrive on one interface and leave via another (wgcf);
	// strict reverse-path filtering would drop them. The kernel uses
	// max(conf.all.rp_filter, conf.<iface>.rp_filter) per ingress, so all=0 alone is
	// NOT enough when a host hardening drop-in pins default.rp_filter=2 — the egress
	// interface inherits 2 at creation and wins over all=0. Pin the egress iface to 0.
	steps = append(steps,
		sysctl("net.ipv4.conf.all.rp_filter", "0"),
		sysctl("net.ipv4.conf.default.rp_filter", "0"),
		sysctl("net.ipv4.conf."+spec.EgressInterface+".rp_filter", "0"),
	)

	// an earlier finding: stale conntrack entries remember the old path; flush so the new
	// egress takes effect immediately instead of after a timeout. BestEffort:
	// `conntrack -D` exits non-zero ("0 flow entries have been deleted") on a fresh
	// node with an empty table, which must NOT abort the first routing reconcile.
	steps = append(steps, Step{
		Summary:    "flush conntrack so routing changes take effect now",
		Argv:       []string{"conntrack", "-D"},
		BestEffort: true,
	})

	// an earlier finding: traffic back to the master must stay direct, else the master
	// sees a Cloudflare source and drops the peer.
	if spec.MasterIP != "" {
		steps = append(steps, ipRuleReplace(prefMaster,
			fmt.Sprintf("keep traffic to master %s on the main table", spec.MasterIP),
			"to", spec.MasterIP, "lookup", "main",
		)...)
	}

	// an earlier finding: private/RU/own networks go direct, never through egress.
	for i, cidr := range spec.DirectCIDRs {
		steps = append(steps, ipRuleReplace(prefDirect0+i,
			fmt.Sprintf("direct route for %s", cidr),
			"to", cidr, "lookup", "main",
		)...)
	}

	// an earlier finding: WG handshake/reply packets are marked by source port in
	// nftables mangle and kept on the main table via this fwmark rule.
	steps = append(steps, ipRuleReplace(prefFwmark,
		fmt.Sprintf("keep fwmark 0x%x (WG replies/handshake) on main", mark),
		"fwmark", fmt.Sprintf("0x%x", mark), "lookup", "main",
	)...)

	// Send CLIENT traffic (and only client traffic) to the egress table. The rule
	// MUST be scoped `from <ClientCIDR>`: a bare `lookup` is `from all`, which pulls
	// the node's OWN host traffic — SSH, DNS, image pulls, even the wgcf handshake
	// to Cloudflare — into WARP, cutting the box off the moment WARP is down/blocked
	// (an earlier finding; recovered only via the provider console). With no ClientCIDR we
	// render NO egress rule rather than risk `from all`: client egress won't work,
	// but the host stays reachable.
	if spec.ClientCIDR != "" {
		steps = append(steps, ipRuleReplace(prefEgress,
			fmt.Sprintf("send client traffic (from %s) to the egress table", spec.ClientCIDR),
			"from", spec.ClientCIDR, "lookup", fmt.Sprintf("%d", EgressTable),
		)...)
	}

	// A lifeline is a second client pool on the exit (its own WGServer, distinct
	// from the primary ClientCIDR); when the exit's egress is WARP, its traffic
	// must ALSO reach the egress table, scoped the same way and for the same
	// reason as ClientCIDR (an earlier finding: never `from all`).
	if spec.LifelineCIDR != "" {
		steps = append(steps, ipRuleReplace(prefLifeline,
			fmt.Sprintf("send lifeline client traffic (from %s) to the egress table", spec.LifelineCIDR),
			"from", spec.LifelineCIDR, "lookup", fmt.Sprintf("%d", EgressTable),
		)...)
	}

	// The xray REALITY inbound dials FROM THE HOST, so the `from <ClientCIDR>` rule
	// above does not catch it. Mark-route its outbound (SO_MARK'd by
	// xray) to the egress table so it leaves through WARP like client traffic
	// (ADR-0025). A separate fwmark from the WG-reply mark (prefFwmark, kept on
	// main) — different mark, different table.
	if spec.RealityEgressMark > 0 {
		steps = append(steps, ipRuleReplace(prefRealityEgress,
			fmt.Sprintf("send reality egress (fwmark 0x%x) to the egress table", spec.RealityEgressMark),
			"fwmark", fmt.Sprintf("0x%x", spec.RealityEgressMark), "lookup", fmt.Sprintf("%d", EgressTable),
		)...)
	}

	// The egress table needs its default route whenever anything is routed into it:
	// client traffic (ClientCIDR), lifeline traffic (LifelineCIDR), and/or the
	// reality-marked host traffic.
	if spec.ClientCIDR != "" || spec.LifelineCIDR != "" || spec.RealityEgressMark > 0 {
		steps = append(steps, Step{
			Summary: fmt.Sprintf("default route via %s in table %d", spec.EgressInterface, EgressTable),
			Argv:    []string{"ip", "route", "replace", "default", "dev", spec.EgressInterface, "table", fmt.Sprintf("%d", EgressTable)},
		})
	}

	return steps, nil
}

// Script serializes steps into a deterministic, one-command-per-line blob. It is
// the canonical text form of the routing intent: the reconcile layer writes it
// to a state file and diffs it, so the routing commands (and the conntrack flush
// in particular, an earlier finding) run only when the intent actually changes rather than
// on every pass.
func Script(steps []Step) string {
	var b strings.Builder
	for _, s := range steps {
		b.WriteString(strings.Join(s.Argv, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// TeardownActions reverses Render: it flushes the egress routing table and
// deletes the ip rules pointing at it, plus flushes conntrack so the old WARP
// path is forgotten immediately (an earlier finding, in reverse).
//
// Two callers: decommissioning an exit, and the WARP→direct failover (ADR-0017),
// where "render nothing" had been mistaken for "undo the previous something" and
// the WARP rules survived a failover that was supposed to abandon them.
//
// Every step is BestEffort, and that is load-bearing rather than tidy. On the
// failover path this runs on a node that may never have had WARP rules at all, and
// `ip rule del` answers non-zero when the rule is not there — an intolerant step
// would fail the reconcile pass of every direct-egress exit on its first pass.
// The comment claimed the deletes tolerated that long before the flag did.
func TeardownActions() []Step {
	return []Step{
		{Summary: fmt.Sprintf("flush egress routing table %d", EgressTable),
			Argv:       []string{"ip", "route", "flush", "table", fmt.Sprintf("%d", EgressTable)},
			BestEffort: true},
		// One delete per PRIORITY, not a single `del lookup <table>`.
		//
		// Render can point two rules at the egress table — prefEgress (`from <pool>`)
		// and prefRealityEgress (`fwmark <mark>`) — and `ip rule del lookup <table>`
		// removes one match and cannot say which. On a WARP→direct failover on an exit
		// carrying REALITY that left one rule standing: the table was flushed so
		// lookups fell through, but the kernel stopped matching what ManagedPrefs and
		// the next ipRuleReplace believed about it, while this function's own comment
		// called itself the exact inverse of Render. Deleting by priority names exactly
		// what Render installed, and each is best-effort so a priority that was never
		// installed costs nothing.
		{Summary: fmt.Sprintf("remove the client egress rule (pref %d)", prefEgress),
			Argv:       []string{"ip", "rule", "del", "pref", fmt.Sprintf("%d", prefEgress)},
			BestEffort: true},
		{Summary: fmt.Sprintf("remove the lifeline egress rule (pref %d)", prefLifeline),
			Argv:       []string{"ip", "rule", "del", "pref", fmt.Sprintf("%d", prefLifeline)},
			BestEffort: true},
		{Summary: fmt.Sprintf("remove the REALITY egress rule (pref %d)", prefRealityEgress),
			Argv:       []string{"ip", "rule", "del", "pref", fmt.Sprintf("%d", prefRealityEgress)},
			BestEffort: true},
		{Summary: "flush conntrack (forget the WARP path)",
			Argv:       []string{"conntrack", "-F"},
			BestEffort: true},
	}
}

// ManagedPrefs returns the ip-rule priorities Render installs for spec, in the
// same order. Exported so the live-kernel drift probe can verify every one is
// still present in the kernel; a direct-egress spec installs none.
func ManagedPrefs(spec domain.RoutingSpec) []int {
	if spec.EgressInterface == "" {
		return nil
	}
	var prefs []int
	if spec.MasterIP != "" {
		prefs = append(prefs, prefMaster)
	}
	for i := range spec.DirectCIDRs {
		prefs = append(prefs, prefDirect0+i)
	}
	prefs = append(prefs, prefFwmark)
	// prefEgress is only installed when there is a client source subnet to scope it
	// to (Render skips it otherwise), so only expect it then.
	if spec.ClientCIDR != "" {
		prefs = append(prefs, prefEgress)
	}
	// prefLifeline is only installed when the exit has a lifeline pool (Render
	// skips it otherwise), same rationale as prefEgress above.
	if spec.LifelineCIDR != "" {
		prefs = append(prefs, prefLifeline)
	}
	if spec.RealityEgressMark > 0 {
		prefs = append(prefs, prefRealityEgress)
	}
	return prefs
}

// KernelReflects reports whether the live kernel still satisfies the routing
// intent, given the raw output of `ip rule list` and `ip route show table
// <EgressTable>`. It is the read-only counterpart to Render: every managed
// ip-rule priority must be present and the egress table must hold a default
// route via the egress interface. When it returns false the planner re-applies
// the full idempotent set — this catches drift the state-file gate cannot (the
// file still matches the intent while someone flushed or edited the kernel
// rules by hand). Pure (no exec) so it is fully testable; the exec that captures
// the two outputs lives in the agent. A direct-egress spec is trivially
// reflected (nothing to route).
func KernelReflects(spec domain.RoutingSpec, ruleList, egressRoutes string) bool {
	if spec.EgressInterface == "" {
		return true
	}
	present := parseRulePrefs(ruleList)
	for _, p := range ManagedPrefs(spec) {
		if !present[p] {
			return false
		}
	}
	// The egress default route only exists when client or lifeline traffic is
	// actually routed (ClientCIDR and/or LifelineCIDR set); without either there
	// is nothing to verify in the egress table.
	if spec.ClientCIDR == "" && spec.LifelineCIDR == "" {
		return true
	}
	return strings.Contains(egressRoutes, "default") &&
		strings.Contains(egressRoutes, spec.EgressInterface)
}

// parseRulePrefs extracts the set of rule priorities present in `ip rule list`
// output. Each line begins with the priority followed by a colon, e.g.
// "300:\tfrom all lookup 51820"; lines without a leading numeric pref are
// skipped.
func parseRulePrefs(ruleList string) map[int]bool {
	prefs := make(map[int]bool)
	for _, line := range strings.Split(ruleList, "\n") {
		field, _, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		if p, err := strconv.Atoi(field); err == nil {
			prefs[p] = true
		}
	}
	return prefs
}

func sysctl(key, val string) Step {
	return Step{
		Summary: fmt.Sprintf("set %s=%s", key, val),
		Argv:    []string{"sysctl", "-w", fmt.Sprintf("%s=%s", key, val)},
	}
}

// ipRuleReplace renders a rule at a fixed priority as a delete-by-pref then add.
// Deleting by priority (best-effort, tolerated when absent) clears whatever rule
// currently occupies that pref — including one with a now-stale selector after
// the spec changed — so the following add installs exactly one current copy and
// nothing leaks across reconciles. selector is the match part (without "pref").
func ipRuleReplace(pref int, summary string, selector ...string) []Step {
	p := fmt.Sprintf("%d", pref)
	add := append(append([]string{"ip", "rule", "add"}, selector...), "pref", p)
	return []Step{
		{
			Summary:    fmt.Sprintf("clear any existing rule at pref %d", pref),
			Argv:       []string{"ip", "rule", "del", "pref", p},
			BestEffort: true,
		},
		{Summary: summary, Argv: add},
	}
}
