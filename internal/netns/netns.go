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

// linkIsUp reads the STATE column of `ip -br link show`. Takes the runner's two
// results directly so the call site stays one line.
func linkIsUp(out string, err error) bool {
	if err != nil {
		return false
	}
	fields := strings.Fields(out)
	return len(fields) >= 2 && fields[1] == "UP"
}

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
	// ProbeHost is the address Ready reaches for from inside the namespace to prove
	// it has a working path to an exit. Empty ⇒ that check is skipped.
	ProbeHost string
	// ProbeResolver is the resolver Ready queries from inside the namespace, as
	// host:port, and ProbeBin is the binary that asks it. Both empty ⇒ the DNS check
	// is skipped, which is honest: without knowing WHICH resolver mihomo will use in
	// there, the question has no answer worth acting on.
	ProbeResolver string
	ProbeBin      string
	// MTU is set on BOTH ends of the veth when non-zero. Production says leave it
	// at zero: mihomo's tunnel traffic to the exits is generated INSIDE the
	// namespace and must leave through this veth whole, so a veth sized to the
	// CLIENT tunnel silently drops every full-size tunnel packet while letting the
	// small handshakes through — tunnels that look up and carry nothing (see
	// netnsLinkMTU in internal/agent/master).
	MTU int
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

	// The veth, checked at BOTH ends.
	//
	// The host end existing does not mean the pair is built: the two commands that
	// build it are separate, and an agent that died between them — a restart, a
	// reboot, an OOM kill — leaves the peer sitting in the host namespace with the
	// same name. Every later step then runs `nsenter … dev mih0` against a namespace
	// that has no such interface and fails forever, while this check says the link
	// is fine because it only ever looked at its own side.
	//
	// So: if the far end is not INSIDE, rebuild. `ip link del` on the host end
	// removes both halves of a pair, which makes the repair one command rather than
	// a case analysis of which half survived.
	_, hostErr := run(ctx, "ip", "-br", "link", "show", in.HostIface)
	_, peerErr := run(ctx, "nsenter", nsArgs("-br", "link", "show", in.PeerIface)...)
	switch {
	case hostErr != nil:
		add("create the veth to mihomo's namespace",
			"ip", "link", "add", in.HostIface, "type", "veth", "peer", "name", in.PeerIface)
		// Move the far end in. Only meaningful right after creation: once it is inside
		// the namespace it is not visible here to move again.
		add("move the far end into the namespace",
			"ip", "link", "set", in.PeerIface, "netns", nsPathPID(nsPath))
	case peerErr != nil:
		add("remove a half-built veth (the far end never reached the namespace)",
			"ip", "link", "del", in.HostIface)
		add("create the veth to mihomo's namespace",
			"ip", "link", "add", in.HostIface, "type", "veth", "peer", "name", in.PeerIface)
		add("move the far end into the namespace",
			"ip", "link", "set", in.PeerIface, "netns", nsPathPID(nsPath))
	}

	if out, err := run(ctx, "ip", "-br", "addr", "show", in.HostIface); err != nil || !strings.Contains(out, hostAddr) {
		add("address the host end "+hostAddr, "ip", "addr", "add", hostAddr, "dev", in.HostIface)
	}
	// `ip -br link show` prints `<name> <STATE> <mac> <FLAGS>`; the STATE column is
	// what says whether the link is up. Matching "UP" anywhere in the line matches
	// the UP flag inside `<NO-CARRIER,BROADCAST,MULTICAST,UP>` too, which is a
	// DOWN link that has been asked to come up — right by accident today, wrong the
	// first time it matters.
	if !linkIsUp(run(ctx, "ip", "-br", "link", "show", in.HostIface)) {
		add("bring the host end up", "ip", "link", "set", in.HostIface, "up")
	}

	if out, err := run(ctx, "nsenter", nsArgs("-br", "addr", "show", in.PeerIface)...); err != nil || !strings.Contains(out, peerAddr) {
		add("address the namespace end "+peerAddr, append([]string{"nsenter"}, nsArgs("addr", "add", peerAddr, "dev", in.PeerIface)...)...)
		add("bring the namespace end up", append([]string{"nsenter"}, nsArgs("link", "set", in.PeerIface, "up")...)...)
	}

	// The MTU, on both ends, when one was asked for. `ip link set mtu` is idempotent
	// but the engine counts every exec as a change, so it is gated on the value the
	// kernel reports.
	if in.MTU > 0 {
		mtu := strconv.Itoa(in.MTU)
		// `ip -br link show` does not print the MTU at all, so a brief read here matched
		// nothing and re-set the MTU on every pass — a change reported forever over a
		// value that was already right. Measured on the stand 2026-09-05.
		if out, err := run(ctx, "ip", "link", "show", in.HostIface); err != nil || !strings.Contains(out, " mtu "+mtu+" ") {
			add("set the host end MTU to "+mtu, "ip", "link", "set", in.HostIface, "mtu", mtu)
		}
		if out, err := run(ctx, "nsenter", nsArgs("link", "show", in.PeerIface)...); err != nil || !strings.Contains(out, " mtu "+mtu+" ") {
			add("set the namespace end MTU to "+mtu, append([]string{"nsenter"}, nsArgs("link", "set", in.PeerIface, "mtu", mtu)...)...)
		}
	}

	// Forwarding, inside the namespace. Everything that is not TCP or UDP — client
	// ICMP above all — is not intercepted by the rules in there; it arrives on the
	// veth addressed to somewhere else and needs the namespace to pass it on. A
	// fresh namespace has ip_forward at 0, so without this those protocols simply
	// stop working the moment the interception moves, which the client-path prober
	// cannot see: its gateway ping is answered locally and never enters the
	// namespace at all.
	if out, err := run(ctx, "nsenter", "--net="+nsPath, "sysctl", "-n", "net.ipv4.ip_forward"); err != nil || strings.TrimSpace(out) != "1" {
		add("let the namespace forward what it does not intercept",
			"nsenter", "--net="+nsPath, "sysctl", "-w", "net.ipv4.ip_forward=1")
	}
	// Reverse-path filtering, pinned rather than inherited. The default a new
	// namespace gets depends on the host's `all`/`default` values at the moment it
	// was created, so it is one of those settings that is whatever the last
	// hardening drop-in left it as. Strict mode here would drop client traffic
	// outright: it arrives on the veth with a client-pool source, and the route back
	// to that pool is over the same veth only because we put it there.
	//
	// All three keys, because the kernel takes the MAXIMUM of `all` and the
	// interface's own value — setting `all` to 0 while the interface sits at 2 leaves
	// loose filtering in force, which is what this namespace actually had: `all=0`,
	// `mih0=2`, `default=2`. Harmless while the namespace has one interface and one
	// route back, and a silent one-way drop the day it has two.
	for _, key := range []string{
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
		"net.ipv4.conf." + in.PeerIface + ".rp_filter",
	} {
		if out, err := run(ctx, "nsenter", "--net="+nsPath, "sysctl", "-n", key); err != nil || strings.TrimSpace(out) != "0" {
			add("stop the namespace reverse-path filtering client traffic ("+key+")",
				"nsenter", "--net="+nsPath, "sysctl", "-w", key+"=0")
		}
	}

	// Two routes, and both are load-bearing: out to the world so mihomo can reach
	// the exits, and back to the client pool so its replies reach the client
	// interface. Without the second, a reply leaves the namespace and is dropped
	// for want of a route — the same silent one-way failure in a new place.
	gw := hostIP(hostAddr)
	routes, _ := run(ctx, "nsenter", nsArgs("route", "show")...)
	// The pool in the form the KERNEL prints it. `ip route show` canonicalises, so
	// a manifest that says `10.80.0.1/24` would never match the `10.80.0.0/24` in
	// the output and the route would be replaced on every pass — a change reported
	// forever over a route that was already right. master_nat.go canonicalises for
	// the same reason.
	clientCIDR := in.ClientCIDR
	if p, perr := netip.ParsePrefix(clientCIDR); perr == nil {
		clientCIDR = p.Masked().String()
	}
	for _, want := range []struct{ dst, match, why string }{
		{"default", "default via " + gw, "reach the exits"},
		{clientCIDR, clientCIDR + " via " + gw, "return traffic to clients"},
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
	// DNS, asked of a NAMED resolver rather than of the system.
	//
	// This check used to run `getent hosts` inside the namespace, and that cannot
	// work: `nsenter --net` changes only the NETWORK namespace, so the lookup still
	// reads the HOST's /etc/resolv.conf. On a systemd box that names 127.0.0.53, a
	// stub resolver which inside this namespace is a loopback with nothing on it —
	// so the gate failed on every master with systemd-resolved, whatever the
	// namespace could actually do. Measured on the stand 2026-09-05.
	//
	// The resolver to ask is the one mihomo will be pointed at once it moves, which
	// only the agent knows. Asking that specific address is also the stronger
	// question: it is the trap this check exists for — mihomo's own resolver
	// configuration pointing at a loopback that is not the one it thinks it is.
	if in.ProbeResolver != "" && in.ProbeBin != "" {
		if _, err := run(ctx, "nsenter", "--net="+nsPath, in.ProbeBin, "-dns-probe", in.ProbeResolver); err != nil {
			return fmt.Errorf("namespace %s cannot resolve through %s: %w", in.Holder, in.ProbeResolver, err)
		}
	}
	// Reachability of the WIRE, not of a route table — and by ICMP, because there
	// is nothing else to ask.
	//
	// This check used to open a TCP connection to the exit's endpoint with bash's
	// /dev/tcp. The endpoint is a WireGuard listener: it is UDP, nothing is on that
	// port over TCP, and the dial could only ever time out. Measured on the stand
	// 2026-09-05 — the gate never passed, so the migration never started, and the
	// three blockers that would have made it fail were being hidden by a fourth.
	//
	// ICMP is the honest question at this layer: before mihomo moves there is no
	// TCP service of ours out there to talk to, and what the namespace needs to
	// demonstrate is that a packet it sends reaches the far node and comes back.
	// It also removes the shell from the probe entirely, and with it the injection
	// surface that made the address parsing necessary — the parsing stays, because
	// an address that is not an address is still a spec we should refuse.
	if in.ProbeHost != "" {
		addr, perr := netip.ParseAddr(in.ProbeHost)
		if perr != nil {
			return fmt.Errorf("netns: probe host %q is not an IP address: %w", in.ProbeHost, perr)
		}
		if _, err := run(ctx, "nsenter", "--net="+nsPath,
			"ping", "-c", "2", "-W", "2", "-q", addr.String()); err != nil {
			return fmt.Errorf("namespace %s cannot reach %s: %w", in.Holder, addr, err)
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

// LinkAddrs derives the host and namespace addresses from a link prefix, so a
// caller that needs to name the namespace end (to point rules or routes at it)
// does not have to reimplement the split.
func LinkAddrs(cidr string) (host, peer string, err error) {
	return Input{CIDR: cidr}.addrs()
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
