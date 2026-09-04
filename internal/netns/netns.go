// Package netns builds and inspects the network namespace mihomo runs in.
//
// It exists because of one kernel rule with a large consequence: mihomo's TPROXY
// reply path binds the SERVER's address:port to send a reply back with the right
// source, so any UDP port the HOST already holds is unreachable for client traffic
// to that port. On the live master that was 443 — the client AmneziaWG interface —
// and every client QUIC flow was one-way for eight days. Giving mihomo a namespace
// of its own removes the collision as a category rather than fixing one port.
//
// Everything here is idempotent and injectable. Ensure runs on every reconcile
// pass, so "already built" has to cost nothing and change nothing: rebuilding the
// veth under a running mihomo every 30 seconds would be the outage this feature
// exists to prevent, delivered on a timer.
package netns

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// Runner executes one command and returns its combined output. Injected so the
// whole package is testable without root, a container runtime or a kernel.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// Exec is the production Runner.
func Exec(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Input describes the namespace link. Every field is required except the probe
// target, which only Ready uses.
type Input struct {
	// Holder is the container whose network namespace mihomo joins. It is a
	// separate container on purpose — the same role Kubernetes gives `pause`.
	// mihomo restarts several times a day (a proxy definition changes, the
	// duplicate-device self-heal fires); if the namespace belonged to mihomo, each
	// restart would take the veth and the rules with it and leave clients with no
	// path until the next reconcile pass noticed.
	Holder string
	// HostIface / PeerIface are the two ends of the veth: the first stays in the
	// host namespace, the second is moved into the holder's.
	HostIface string
	PeerIface string
	// CIDR is the point-to-point link, a /30. The host takes the first usable
	// address and the namespace the second.
	CIDR string
	// ClientCIDR is the client pool, routed from the namespace back through the
	// host so mihomo's replies reach the client interface.
	ClientCIDR string
	// ProbeHost / ProbePort are what Ready dials from inside the namespace to
	// prove it has a working path to an exit. Empty ⇒ that check is skipped.
	ProbeHost string
	ProbePort int
}

// Step is one idempotent command the caller should run. Reads happen during
// planning (like every other planner here probes the live kernel); WRITES are
// returned as data so `--plan` shows exactly what would be done and changes
// nothing. Same shape as internal/routing.Step, for the same reason.
type Step struct {
	Summary string
	Argv    []string
}

// Plan reports the steps that would converge the namespace link. An empty slice
// means the node is already converged — which is the normal case on every
// reconcile pass after the first, and it must cost nothing: rebuilding the veth
// under a running mihomo every 30 seconds would be the outage this feature exists
// to prevent, delivered on a timer.
func Plan(ctx context.Context, in Input, run Runner) ([]Step, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	hostAddr, peerAddr, err := in.addrs()
	if err != nil {
		return nil, err
	}
	nsPath, err := Path(ctx, in.Holder, run)
	if err != nil {
		return nil, err
	}

	var steps []Step
	add := func(summary string, argv ...string) { steps = append(steps, Step{Summary: summary, Argv: argv}) }
	nsArgs := func(rest ...string) []string {
		return append([]string{"--net=" + nsPath, "ip"}, rest...)
	}

	// The veth. `ip -br link show` answering is the whole test: the pair is created
	// together, so if the host end exists the peer was made with it.
	if _, err := run(ctx, "ip", "-br", "link", "show", in.HostIface); err != nil {
		add("create the veth to mihomo's namespace",
			"ip", "link", "add", in.HostIface, "type", "veth", "peer", "name", in.PeerIface)
		// Move the far end in. Only meaningful right after creation: once it is inside
		// the namespace it is not visible here to move again.
		add("move the far end into the namespace",
			"ip", "link", "set", in.PeerIface, "netns", nsPathPID(nsPath))
	}

	if out, err := run(ctx, "ip", "-br", "addr", "show", in.HostIface); err != nil || !strings.Contains(out, hostAddr) {
		add("address the host end "+hostAddr, "ip", "addr", "add", hostAddr, "dev", in.HostIface)
	}
	if out, err := run(ctx, "ip", "-br", "link", "show", in.HostIface); err != nil || !strings.Contains(out, "UP") {
		add("bring the host end up", "ip", "link", "set", in.HostIface, "up")
	}

	if out, err := run(ctx, "nsenter", nsArgs("-br", "addr", "show", in.PeerIface)...); err != nil || !strings.Contains(out, peerAddr) {
		add("address the namespace end "+peerAddr, append([]string{"nsenter"}, nsArgs("addr", "add", peerAddr, "dev", in.PeerIface)...)...)
		add("bring the namespace end up", append([]string{"nsenter"}, nsArgs("link", "set", in.PeerIface, "up")...)...)
	}

	// Two routes, and both are load-bearing: out to the world so mihomo can reach
	// the exits, and back to the client pool so its replies reach the client
	// interface. Without the second, a reply leaves the namespace and is dropped
	// for want of a route — the same silent one-way failure in a new place.
	gw := hostIP(hostAddr)
	routes, _ := run(ctx, "nsenter", nsArgs("route", "show")...)
	for _, want := range []struct{ dst, match, why string }{
		{"default", "default via " + gw, "reach the exits"},
		{in.ClientCIDR, in.ClientCIDR + " via " + gw, "return traffic to clients"},
	} {
		if strings.Contains(routes, want.match) {
			continue
		}
		add("route "+want.dst+" via the host ("+want.why+")",
			append([]string{"nsenter"}, nsArgs("route", "replace", want.dst, "via", gw, "dev", in.PeerIface)...)...)
	}
	return steps, nil
}

// Ready reports whether the namespace is fit to carry client traffic. It is the
// precondition gate for the move: nothing is switched over until every one of
// these answers, because a half-migrated master is worse than an unmigrated one.
func Ready(ctx context.Context, in Input, run Runner) error {
	nsPath, err := Path(ctx, in.Holder, run)
	if err != nil {
		return err
	}
	// DNS. mihomo resolves through the fleet resolver, which lives in the HOST
	// namespace — so this is the check that catches the `127.0.0.1:53` trap, where
	// the loopback mihomo asks is its own and nothing is listening on it.
	if _, err := run(ctx, "nsenter", "--net="+nsPath, "getent", "hosts", "cloudflare.com"); err != nil {
		return fmt.Errorf("namespace %s cannot resolve DNS: %w", in.Holder, err)
	}
	// A real connection to an exit. Reachability of the wire, not of a route table.
	if in.ProbeHost != "" && in.ProbePort > 0 {
		target := fmt.Sprintf("%s/%d", in.ProbeHost, in.ProbePort)
		if _, err := run(ctx, "nsenter", "--net="+nsPath, "timeout", "5",
			"bash", "-c", "exec 3<>/dev/tcp/"+target); err != nil {
			return fmt.Errorf("namespace %s cannot reach %s:%d: %w", in.Holder, in.ProbeHost, in.ProbePort, err)
		}
	}
	return nil
}

// Path returns the holder's network-namespace path, failing when the container is
// absent or stopped. A stopped container reports PID 0, and /proc/0/ns/net is the
// host's own namespace — building a link there would quietly put the veth peer
// back where it started.
func Path(ctx context.Context, holder string, run Runner) (string, error) {
	out, err := run(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", holder)
	if err != nil {
		return "", fmt.Errorf("namespace holder %q not found: %w", holder, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || pid <= 0 {
		return "", fmt.Errorf("namespace holder %q is not running (pid %q)", holder, strings.TrimSpace(out))
	}
	return fmt.Sprintf("/proc/%d/ns/net", pid), nil
}

func nsPathPID(nsPath string) string {
	trimmed := strings.TrimPrefix(nsPath, "/proc/")
	pid, _, _ := strings.Cut(trimmed, "/")
	return pid
}

func (in Input) validate() error {
	for _, f := range []struct{ name, val string }{
		{"holder", in.Holder}, {"host interface", in.HostIface},
		{"peer interface", in.PeerIface}, {"link CIDR", in.CIDR},
		{"client CIDR", in.ClientCIDR},
	} {
		if f.val == "" {
			return fmt.Errorf("netns: %s is required", f.name)
		}
	}
	return nil
}

// addrs derives the two ends from the link prefix: host .1, namespace .2. A /30
// is the natural shape — two usable addresses, no room for a third party.
func (in Input) addrs() (host, peer string, err error) {
	p, err := netip.ParsePrefix(in.CIDR)
	if err != nil {
		return "", "", fmt.Errorf("netns: link CIDR %q: %w", in.CIDR, err)
	}
	if !p.Addr().Is4() {
		return "", "", fmt.Errorf("netns: link CIDR %q must be IPv4", in.CIDR)
	}
	base := p.Masked().Addr()
	h := base.Next()
	n := h.Next()
	if !p.Contains(h) || !p.Contains(n) {
		return "", "", fmt.Errorf("netns: link CIDR %q is too small for two addresses", in.CIDR)
	}
	bits := p.Bits()
	return fmt.Sprintf("%s/%d", h, bits), fmt.Sprintf("%s/%d", n, bits), nil
}

func hostIP(cidr string) string {
	addr, _, _ := strings.Cut(cidr, "/")
	return addr
}
