// Package dockerfw provides the shared DOCKER-USER forwarding reconciler used by
// both the master and exit agents. Docker sets the nft filter FORWARD policy to
// DROP and accepts only its own bridge traffic, so client packets routed through
// a WG interface to the uplink/egress are dropped in the forward hook while the
// AmneziaWG handshake (an INPUT match, not forward) keeps looking healthy.
// A node's own `inet wgfleet` forward chain cannot override this —
// a drop in Docker's base chain is final regardless of an accept in another base
// chain at the same hook. The sanctioned fix is an ACCEPT in DOCKER-USER, which
// Docker never flushes. The exit and master differ only in the client interface
// (awg0 vs wg0) and a label, so they share this planner.
package dockerfw

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// ForwardPlanner keeps a node forwarding client traffic despite Docker's FORWARD
// drop policy: it asserts net.ipv4.ip_forward and inserts two DOCKER-USER accepts
// (client→outbound and the established/related return path) once the DOCKER-USER
// chain exists. Idempotent and self-healing; defers (never fails) while Docker is
// not up yet.
type ForwardPlanner struct {
	component    string
	iface        string
	forwardLabel string
	// extra are additional interfaces that must be allowed across the FORWARD path.
	extra []string // summary for the client→outbound accept rule
	// Probes (nil ⇒ real); injected in tests.
	forwardOn   func() bool
	chainExists func() bool
	rulePresent func(m []string) bool
}

// NewForwardPlanner builds a ForwardPlanner. iface is the client-facing WG
// interface; if empty it falls back to fallbackIface. component is the reconcile
// component label; forwardLabel is the summary for the client→outbound accept.
func NewForwardPlanner(component, iface, fallbackIface, forwardLabel string, extra ...string) ForwardPlanner {
	if iface == "" {
		iface = fallbackIface
	}
	return ForwardPlanner{component: component, iface: iface, forwardLabel: forwardLabel, extra: extra}
}

func (p ForwardPlanner) Component() string { return p.component }

func (p ForwardPlanner) Plan(_ context.Context, _ domain.NodeSpec) ([]reconcile.Action, error) {
	var actions []reconcile.Action

	// 1. IPv4 forwarding (Docker enables it, but the data plane must not depend on
	// that side effect, so we assert it).
	if p.isForwardOn() {
		actions = append(actions, reconcile.NoChangeAction("ip_forward", "already enabled"))
	} else {
		actions = append(actions, reconcile.ExecAction("enable IPv4 forwarding",
			"sysctl", "-w", "net.ipv4.ip_forward=1"))
	}

	// 2. DOCKER-USER accept rules. The chain exists only once Docker is up; until
	// then defer rather than fail the pass (the compose planner brings Docker up
	// earlier in the same reconcile, so it converges next pass at the latest).
	if !p.dockerUserExists() {
		actions = append(actions, reconcile.NoChangeAction("DOCKER-USER",
			"pending: DOCKER-USER chain not present yet (docker not up)"))
		return actions, nil
	}
	rules := []struct {
		summary string
		match   []string
	}{
		{p.forwardLabel, []string{"-i", p.iface, "-j", "ACCEPT"}},
		{"accept return traffic to clients (DOCKER-USER)", []string{"-o", p.iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
	}
	// Any further interface that has to cross this chain — today, the veth to
	// mihomo's network namespace.
	//
	// Docker sets the FORWARD policy to DROP, so everything that is not explicitly
	// accepted here dies silently between two interfaces the operator never
	// configured. Measured on the stand: with the veth
	// missing from this list the namespace could not reach a single address off the
	// host, its readiness gate never passed, and the migration never started — while
	// every rule the agent renders in nftables looked exactly right.
	for _, iface := range p.extra {
		if iface == "" || iface == p.iface {
			continue
		}
		rules = append(rules,
			struct {
				summary string
				match   []string
			}{"accept " + iface + " → uplink forwarding (DOCKER-USER)", []string{"-i", iface, "-j", "ACCEPT"}},
			struct {
				summary string
				match   []string
			}{"accept return traffic to " + iface + " (DOCKER-USER)", []string{"-o", iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
		)
	}
	for _, r := range rules {
		if p.isRulePresent(r.match) {
			actions = append(actions, reconcile.NoChangeAction("DOCKER-USER", r.summary+" already present"))
			continue
		}
		argv := append([]string{"iptables", "-I", "DOCKER-USER"}, r.match...)
		actions = append(actions, reconcile.ExecAction(r.summary, argv...))
	}
	return actions, nil
}

func (p ForwardPlanner) isForwardOn() bool {
	if p.forwardOn != nil {
		return p.forwardOn()
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

func (p ForwardPlanner) dockerUserExists() bool {
	if p.chainExists != nil {
		return p.chainExists()
	}
	return exec.Command("iptables", "-S", "DOCKER-USER").Run() == nil
}

func (p ForwardPlanner) isRulePresent(match []string) bool {
	if p.rulePresent != nil {
		return p.rulePresent(match)
	}
	argv := append([]string{"-C", "DOCKER-USER"}, match...)
	return exec.Command("iptables", argv...).Run() == nil
}
