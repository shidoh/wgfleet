package netns

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// recorder is a Runner that answers from a script and remembers what was asked.
type recorder struct {
	out   map[string]string // command line -> stdout
	fail  map[string]bool   // command line -> return an error
	calls []string
}

// run models a real box: a READ of something that does not exist fails, a WRITE
// succeeds unless the script says otherwise. Returning empty-and-nil for an
// unknown read would tell Ensure the object is already there and every build step
// would be skipped — a stub that agrees with whatever it is asked.
func (r *recorder) run(_ context.Context, name string, args ...string) (string, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, line)
	if r.fail[line] {
		return "", errors.New("command failed: " + line)
	}
	if out, ok := r.out[line]; ok {
		return out, nil
	}
	if isRead(line) {
		return "", errors.New("no such object: " + line)
	}
	return "", nil
}

func isRead(line string) bool {
	return strings.Contains(line, " show") || strings.Contains(line, "docker inspect") ||
		strings.Contains(line, "sysctl -n") || strings.Contains(line, " rule list")
}

func (r *recorder) mutating() []string {
	var out []string
	for _, c := range r.calls {
		// Reads are how Ensure decides; only writes count as "did something".
		if isRead(c) {
			continue
		}
		if strings.Contains(c, " link add ") || strings.Contains(c, " addr add ") ||
			strings.Contains(c, " link set ") || strings.Contains(c, " route ") {
			out = append(out, c)
		}
	}
	return out
}

func testInput() Input {
	return Input{
		Holder: "wgfleet-netns", HostIface: "mih-host", PeerIface: "mih0",
		CIDR: "100.127.255.0/30", ClientCIDR: "10.73.0.0/24",
	}
}

// A converged node must be left alone. Ensure runs every reconcile pass; if it
// re-created the veth each time, the namespace would be rebuilt under a running
// mihomo every 30 seconds — which is the data-plane outage this whole feature
// exists to avoid, delivered on a timer.
func TestEnsureIsIdempotent(t *testing.T) {
	r := &recorder{out: map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns":                            "4242\n",
		"ip -br link show mih-host":                                                 "mih-host@if9 UP 100.127.255.1/30\n",
		"ip -br addr show mih-host":                                                 "mih-host@if9 UP 100.127.255.1/30\n",
		"nsenter --net=/proc/4242/ns/net ip -br addr show mih0":                     "mih0@if8 UP 100.127.255.2/30\n",
		"nsenter --net=/proc/4242/ns/net ip -br link show mih0":                     "mih0@if8 UP 100.127.255.2/30\n",
		"nsenter --net=/proc/4242/ns/net ip route show":                             "default via 100.127.255.1 dev mih0\n10.73.0.0/24 via 100.127.255.1 dev mih0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.ip_forward":             "1\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.all.rp_filter":     "0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.default.rp_filter": "0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.mih0.rp_filter":    "0\n",
	}}

	steps, err := Plan(context.Background(), testInput(), r.run)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("a converged namespace would be rebuilt anyway:\n  %s", strings.Join(argvs(steps), "\n  "))
	}
	if got := r.mutating(); len(got) != 0 {
		t.Errorf("planning executed a write:\n  %s", strings.Join(got, "\n  "))
	}
}

// On a node that has nothing yet, Ensure must build the whole link: veth, both
// addresses, both ends up, and the routes that make the namespace reachable in
// each direction.
func TestEnsureBuildsTheLinkFromNothing(t *testing.T) {
	r := &recorder{out: map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns": "4242\n",
	}}

	steps, err := Plan(context.Background(), testInput(), r.run)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(steps) == 0 {
		t.Fatal("building the link from nothing produced no steps")
	}
	// Planning must not touch the box: the steps are data until someone applies them.
	if got := r.mutating(); len(got) != 0 {
		t.Errorf("planning executed a write:\n  %s", strings.Join(got, "\n  "))
	}
	want := []string{
		"ip link add mih-host type veth peer name mih0",
		"ip link set mih0 netns 4242",
		"ip addr add 100.127.255.1/30 dev mih-host",
		"ip link set mih-host up",
		"nsenter --net=/proc/4242/ns/net ip addr add 100.127.255.2/30 dev mih0",
		"nsenter --net=/proc/4242/ns/net ip link set mih0 up",
		"nsenter --net=/proc/4242/ns/net ip route replace default via 100.127.255.1 dev mih0",
		"nsenter --net=/proc/4242/ns/net ip route replace 10.73.0.0/24 via 100.127.255.1 dev mih0",
	}
	joined := strings.Join(argvs(steps), "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("missing step %q in:\n%s", w, joined)
		}
	}
}

func argvs(steps []Step) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, strings.Join(s.Argv, " "))
	}
	return out
}

// Without a holder there is no namespace, and every later step would address
// /proc//ns/net — a path that is not an error, just wrong. Fail loudly instead.
func TestEnsureRefusesWithoutAHolder(t *testing.T) {
	r := &recorder{fail: map[string]bool{
		"docker inspect -f {{.State.Pid}} wgfleet-netns": true,
	}}
	if _, err := Plan(context.Background(), testInput(), r.run); err == nil {
		t.Fatal("a missing holder container was accepted")
	}
	if got := r.mutating(); len(got) != 0 {
		t.Errorf("changes were made before the holder was confirmed:\n  %s", strings.Join(got, "\n  "))
	}
}

// A holder that exists but is not running reports PID 0. Building a namespace
// around PID 0 addresses the host's own namespace — that would put the veth peer
// back where it started and silently do nothing useful.
func TestEnsureRefusesAStoppedHolder(t *testing.T) {
	r := &recorder{out: map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns": "0\n",
	}}
	if _, err := Plan(context.Background(), testInput(), r.run); err == nil {
		t.Fatal("a stopped holder (pid 0) was accepted")
	}
}

// Ready is the precondition gate for the move. It must check the three things
// that actually break: the namespace resolves DNS, it can open a connection to an
// exit. Reachability is ICMP: the exit's endpoint is a WireGuard listener, so
// there is no TCP service there to dial, and the dial that used to be attempted
// could only ever time out.
func TestReadyChecksDNSEgressAndSourceAddress(t *testing.T) {
	base := map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns": "4242\n",
	}
	in := testInput()
	in.ProbeHost = "203.0.113.9"
	in.ProbeResolver = "10.80.0.1:53"
	in.ProbeBin = "/usr/local/bin/wgfleet-agent"

	t.Run("both pass", func(t *testing.T) {
		r := &recorder{out: base}
		if err := Ready(context.Background(), in, r.run); err != nil {
			t.Fatalf("Ready: %v", err)
		}
		joined := strings.Join(r.calls, "\n")
		for _, want := range []string{"-dns-probe 10.80.0.1:53", "203.0.113.9"} {
			if !strings.Contains(joined, want) {
				t.Errorf("Ready never checked %q:\n%s", want, joined)
			}
		}
		// `getent` reads the HOST's resolv.conf even under `nsenter --net`, so it
		// answers a question about the wrong namespace. On a systemd box that is
		// 127.0.0.53, a stub resolver which in here is a loopback with nothing on it.
		if strings.Contains(joined, "getent") {
			t.Errorf("the gate still asks the host's resolver configuration:\n%s", joined)
		}
	})

	t.Run("a namespace with no DNS is not ready", func(t *testing.T) {
		r := &recorder{out: base, fail: map[string]bool{
			"nsenter --net=/proc/4242/ns/net /usr/local/bin/wgfleet-agent -dns-probe 10.80.0.1:53": true,
		}}
		if err := Ready(context.Background(), in, r.run); err == nil {
			t.Fatal("a namespace that cannot resolve was declared ready")
		}
	})

	// Without knowing WHICH resolver mihomo will use in there, the question has no
	// answer worth acting on, so it is skipped rather than guessed at.
	t.Run("no resolver named means no DNS check", func(t *testing.T) {
		bare := in
		bare.ProbeResolver = ""
		r := &recorder{out: base}
		if err := Ready(context.Background(), bare, r.run); err != nil {
			t.Fatalf("Ready: %v", err)
		}
		if strings.Contains(strings.Join(r.calls, "\n"), "dns-probe") {
			t.Error("a DNS check was taken with no resolver to ask")
		}
	})
}

// The probe target must be an IP address and nothing else.
//
// The shell is gone from this probe — the reachability check is ICMP now, so
// there is no word to inject into — but the validation stays. A spec that names a
// hostname here would make a reachability check depend on the resolver it is
// meant to be independent of, and a spec that names nonsense should be refused
// rather than silently skipped.
func TestReadyRefusesAProbeHostThatIsNotAnAddress(t *testing.T) {
	base := map[string]string{"docker inspect -f {{.State.Pid}} wgfleet-netns": "4242\n"}
	for _, bad := range []string{
		"203.0.113.9; rm -rf /",
		"$(id)",
		"`id`",
		"exit.example.com",
	} {
		in := testInput()
		in.ProbeHost = bad
		r := &recorder{out: base}
		if err := Ready(context.Background(), in, r.run); err == nil {
			t.Errorf("probe host %q was accepted", bad)
		}
		for _, c := range r.calls {
			if strings.Contains(c, "/dev/tcp") {
				t.Errorf("probe host %q reached the shell: %q", bad, c)
			}
		}
	}
}

// `ip route show` canonicalises a prefix, so a manifest that names the pool by a
// host address inside it would never match the output and the route would be
// replaced on every pass — a change reported forever over a route that was
// already right.
func TestConvergedRouteIsNotReplacedForANonCanonicalPool(t *testing.T) {
	r := &recorder{out: map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns":                            "4242\n",
		"ip -br link show mih-host":                                                 "mih-host@if9 UP 100.127.255.1/30\n",
		"ip -br addr show mih-host":                                                 "mih-host@if9 UP 100.127.255.1/30\n",
		"nsenter --net=/proc/4242/ns/net ip -br addr show mih0":                     "mih0@if8 UP 100.127.255.2/30\n",
		"nsenter --net=/proc/4242/ns/net ip -br link show mih0":                     "mih0@if8 UP 100.127.255.2/30\n",
		"nsenter --net=/proc/4242/ns/net ip route show":                             "default via 100.127.255.1 dev mih0\n10.73.0.0/24 via 100.127.255.1 dev mih0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.ip_forward":             "1\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.all.rp_filter":     "0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.default.rp_filter": "0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.mih0.rp_filter":    "0\n",
	}}
	in := testInput()
	in.ClientCIDR = "10.73.0.1/24" // the gateway address, not the network address

	steps, err := Plan(context.Background(), in, r.run)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("a converged route was replaced because of how the pool was spelled:\n  %s",
			strings.Join(argvs(steps), "\n  "))
	}
}

// A half-built veth — the pair was created and the agent died before moving the
// far end in — must be rebuilt. Checking only the host side reports it healthy
// while every `nsenter … dev mih0` fails forever.
func TestHalfBuiltVethIsRebuilt(t *testing.T) {
	r := &recorder{out: map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns": "4242\n",
		"ip -br link show mih-host":                      "mih-host@if9 DOWN 100.127.255.1/30\n",
		// The far end is NOT in the namespace: the read fails (default behaviour).
	}}
	steps, err := Plan(context.Background(), testInput(), r.run)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	joined := strings.Join(argvs(steps), "\n")
	if !strings.Contains(joined, "ip link del mih-host") {
		t.Errorf("the half-built pair was left in place:\n%s", joined)
	}
	if !strings.Contains(joined, "ip link add mih-host type veth") {
		t.Errorf("the veth was never rebuilt:\n%s", joined)
	}
}

// A link that is DOWN but carries the UP flag inside its flag list — which is what
// `<NO-CARRIER,BROADCAST,MULTICAST,UP>` is — must still be brought up. Matching
// "UP" anywhere in the line was right by accident.
func TestADownLinkWithTheUPFlagIsStillBroughtUp(t *testing.T) {
	r := &recorder{out: map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns":                            "4242\n",
		"ip -br link show mih-host":                                                 "mih-host@if9 DOWN <NO-CARRIER,BROADCAST,MULTICAST,UP>\n",
		"ip -br addr show mih-host":                                                 "mih-host@if9 DOWN 100.127.255.1/30\n",
		"nsenter --net=/proc/4242/ns/net ip -br link show mih0":                     "mih0@if8 UP\n",
		"nsenter --net=/proc/4242/ns/net ip -br addr show mih0":                     "mih0@if8 UP 100.127.255.2/30\n",
		"nsenter --net=/proc/4242/ns/net ip route show":                             "default via 100.127.255.1 dev mih0\n10.73.0.0/24 via 100.127.255.1 dev mih0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.ip_forward":             "1\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.all.rp_filter":     "0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.default.rp_filter": "0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.mih0.rp_filter":    "0\n",
	}}
	steps, err := Plan(context.Background(), testInput(), r.run)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !strings.Contains(strings.Join(argvs(steps), "\n"), "ip link set mih-host up") {
		t.Errorf("a down link was left down:\n  %s", strings.Join(argvs(steps), "\n  "))
	}
}

// The reachability check must not be a TCP dial. The endpoint it is given is a
// WireGuard listener — UDP — so a TCP connection there can only ever time out,
// and on the stand 2026-09-05 that made the readiness gate impossible to pass and
// the migration impossible to start.
func TestReadyDoesNotDialTCPAtAWireGuardEndpoint(t *testing.T) {
	r := &recorder{out: map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns": "4242\n",
	}}
	in := testInput()
	in.ProbeHost = "203.0.113.9"
	if err := Ready(context.Background(), in, r.run); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	if strings.Contains(joined, "/dev/tcp") || strings.Contains(joined, "bash") {
		t.Errorf("the gate still opens a TCP connection at a UDP listener:\n%s", joined)
	}
	if !strings.Contains(joined, "ping -c 2 -W 2 -q 203.0.113.9") {
		t.Errorf("the gate never reached for the exit at all:\n%s", joined)
	}
}

// An unreachable exit is not ready. The gate exists to stop a move into a
// namespace with no path out.
func TestReadyFailsWhenTheExitCannotBeReached(t *testing.T) {
	r := &recorder{
		out:  map[string]string{"docker inspect -f {{.State.Pid}} wgfleet-netns": "4242\n"},
		fail: map[string]bool{"nsenter --net=/proc/4242/ns/net ping -c 2 -W 2 -q 203.0.113.9": true},
	}
	in := testInput()
	in.ProbeHost = "203.0.113.9"
	if err := Ready(context.Background(), in, r.run); err == nil {
		t.Fatal("a namespace with no path to an exit was declared ready")
	}
}

// The kernel takes the MAXIMUM of `all` and the interface's own rp_filter, so
// setting `all` and stopping there proves nothing.
//
// Measured in the live namespace: all=0, mih0=2, default=2 — loose filtering in
// force while the code believed it had turned filtering off. Harmless with one
// interface and one route back; a silent one-way drop the day there are two.
func TestReversePathFilteringIsPinnedOnEveryKeyTheKernelConsults(t *testing.T) {
	answers := map[string]string{
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.all.rp_filter":     "0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.default.rp_filter": "2\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.mih0.rp_filter":    "2\n",
	}
	base := map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns":                "4242\n",
		"ip -br link show mih-host":                                     "mih-host@if9 UP 100.127.255.1/30\n",
		"ip -br addr show mih-host":                                     "mih-host@if9 UP 100.127.255.1/30\n",
		"nsenter --net=/proc/4242/ns/net ip -br addr show mih0":         "mih0@if8 UP 100.127.255.2/30\n",
		"nsenter --net=/proc/4242/ns/net ip -br link show mih0":         "mih0@if8 UP 100.127.255.2/30\n",
		"nsenter --net=/proc/4242/ns/net ip route show":                 "default via 100.127.255.1 dev mih0\n10.73.0.0/24 via 100.127.255.1 dev mih0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.ip_forward": "1\n",
	}
	for k, v := range answers {
		base[k] = v
	}
	r := &recorder{out: base}
	planned, err := Plan(context.Background(), testInput(), r.run)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	steps := strings.Join(argvs(planned), "\n")
	for _, key := range []string{"net.ipv4.conf.default.rp_filter=0", "net.ipv4.conf.mih0.rp_filter=0"} {
		if !strings.Contains(steps, key) {
			t.Errorf("a key the kernel consults is left alone: %s\n%s", key, steps)
		}
	}
	if strings.Contains(steps, "net.ipv4.conf.all.rp_filter=0") {
		t.Errorf("a key that is already 0 was written again:\n%s", steps)
	}
}
