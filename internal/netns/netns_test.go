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
		"docker inspect -f {{.State.Pid}} wgfleet-netns":                        "4242\n",
		"ip -br link show mih-host":                                             "mih-host@if9 UP 100.127.255.1/30\n",
		"ip -br addr show mih-host":                                             "mih-host@if9 UP 100.127.255.1/30\n",
		"nsenter --net=/proc/4242/ns/net ip -br addr show mih0":                 "mih0@if8 UP 100.127.255.2/30\n",
		"nsenter --net=/proc/4242/ns/net ip -br link show mih0":                 "mih0@if8 UP 100.127.255.2/30\n",
		"nsenter --net=/proc/4242/ns/net ip route show":                         "default via 100.127.255.1 dev mih0\n10.73.0.0/24 via 100.127.255.1 dev mih0\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.ip_forward":         "1\n",
		"nsenter --net=/proc/4242/ns/net sysctl -n net.ipv4.conf.all.rp_filter": "0\n",
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
// exit, and its traffic leaves with the host's address rather than a client one.
func TestReadyChecksDNSEgressAndSourceAddress(t *testing.T) {
	base := map[string]string{
		"docker inspect -f {{.State.Pid}} wgfleet-netns": "4242\n",
	}
	in := testInput()
	in.ProbeHost = "203.0.113.9"
	in.ProbePort = 443

	t.Run("all three pass", func(t *testing.T) {
		r := &recorder{out: base}
		if err := Ready(context.Background(), in, r.run); err != nil {
			t.Fatalf("Ready: %v", err)
		}
		joined := strings.Join(r.calls, "\n")
		for _, want := range []string{"getent", "203.0.113.9"} {
			if !strings.Contains(joined, want) {
				t.Errorf("Ready never checked %q:\n%s", want, joined)
			}
		}
	})

	t.Run("a namespace with no DNS is not ready", func(t *testing.T) {
		r := &recorder{out: base, fail: map[string]bool{}}
		for _, c := range []string{"nsenter --net=/proc/4242/ns/net getent hosts cloudflare.com"} {
			r.fail[c] = true
		}
		if err := Ready(context.Background(), in, r.run); err == nil {
			t.Fatal("a namespace that cannot resolve was declared ready")
		}
	})
}

// The probe target is formatted into a shell word, so it must be an IP address
// and nothing else.
//
// /dev/tcp is a bash builtin, so the shell cannot be avoided without depending on
// a netcat that may not be installed — which means the STRING has to be made safe
// rather than the mechanism. This field is currently set nowhere in production and
// is plainly intended to carry an exit's address later; validating now closes the
// hole before anything is wired to it.
func TestReadyRefusesAProbeHostThatIsNotAnAddress(t *testing.T) {
	base := map[string]string{"docker inspect -f {{.State.Pid}} wgfleet-netns": "4242\n"}
	for _, bad := range []string{
		"203.0.113.9; rm -rf /",
		"$(id)",
		"`id`",
		"exit.example.com",
	} {
		in := testInput()
		in.ProbeHost, in.ProbePort = bad, 443
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

// A port outside the range must be refused for the same reason.
func TestReadyRefusesAProbePortOutOfRange(t *testing.T) {
	in := testInput()
	in.ProbeHost, in.ProbePort = "203.0.113.9", 70000
	r := &recorder{out: map[string]string{"docker inspect -f {{.State.Pid}} wgfleet-netns": "4242\n"}}
	if err := Ready(context.Background(), in, r.run); err == nil {
		t.Error("an out-of-range probe port was accepted")
	}
}
