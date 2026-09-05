package master

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// fullTargets is a master with everything the prober can aim at: a gateway, a
// management address, a direct host, and a binary to re-execute for the UDP probe.
func fullTargets() ClientPathTargets {
	return ClientPathTargets{
		Gateway:  "10.80.0.1",
		MgmtAddr: "172.29.3.10",
		Direct:   []string{"10.0.0.0/8", "203.0.113.7/32", "198.51.100.9/32"},
		SelfExec: "/usr/local/bin/wgfleet-agent",
	}
}

// Every probe must run INSIDE the prober's namespace. One that ran on the host
// would measure the host's own connectivity — which was fine throughout the
// outage — and report the client path healthy while it was dead.
func TestClientPathProbesRunInsideTheProberNamespace(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	probes := MeasureClientPath(context.Background(), fullTargets(), run)
	if len(probes) == 0 {
		t.Fatal("nothing was measured")
	}
	if !ClientPathOK(probes) {
		t.Errorf("all probes succeeded but the verdict is negative: %+v", probes)
	}
	for _, c := range calls {
		if !strings.HasPrefix(c, "ip netns exec "+synthNetns+" ") {
			t.Errorf("a probe ran outside the prober's namespace: %q", c)
		}
	}
}

// The blocker this rewrite exists for. Of the original three probes, two never
// reached mihomo: the gateway ping is answered locally and the DNS probe went
// through resolv.conf to the fleet's own resolver. Nothing crossed the TPROXY
// return path, so the August outage would have been invisible to the instrument
// that is also the judge of the automatic revert.
func TestClientPathMeasuresTheUDPReturnPath(t *testing.T) {
	var sawUDPProbe bool
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, DNSProbeFlag) {
			sawUDPProbe = true
			// The query must name its resolver explicitly; a probe that reads
			// resolv.conf never leaves the tunnel.
			if !strings.Contains(joined, ":53") {
				t.Errorf("the UDP probe does not name a resolver: %q", joined)
			}
		}
		if strings.Contains(joined, "getent") {
			t.Errorf("the UDP probe still goes through resolv.conf: %q", joined)
		}
		return "", nil
	}
	MeasureClientPath(context.Background(), fullTargets(), run)
	if !sawUDPProbe {
		t.Fatal("no probe crossed the UDP return path: the instrument cannot fail on the failure it exists for")
	}
}

// Destinations that must BYPASS the interception are probed too. Routing the
// whole client interface into a namespace takes them with it, and their loss is
// the same shape as the original outage: partial, one-way, and invisible to every
// component metric.
func TestClientPathProbesDestinationsThatMustStayDirect(t *testing.T) {
	var pinged []string
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		if a := strings.Join(args, " "); strings.Contains(a, "ping") {
			pinged = append(pinged, args[len(args)-1])
		}
		return "", nil
	}
	MeasureClientPath(context.Background(), fullTargets(), run)
	want := map[string]bool{"10.80.0.1": false, "172.29.3.10": false, "203.0.113.7": false}
	for _, p := range pinged {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for addr, seen := range want {
		if !seen {
			t.Errorf("%s was never probed; a move that black-holes it would look healthy", addr)
		}
	}
}

// A network prefix has no address worth pinging; only single hosts are probed.
func TestClientPathSkipsDirectPrefixesWithNoHost(t *testing.T) {
	got := hostAddrs([]string{"10.0.0.0/8", "172.29.0.0/16", "203.0.113.7/32", "nonsense"})
	if len(got) != 1 || got[0] != "203.0.113.7" {
		t.Fatalf("got %v, want only the /32", got)
	}
}

// A failing probe must name what failed, and it must not be smoothed over.
func TestClientPathReportsWhichProbeFailed(t *testing.T) {
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "curl") {
			return "", errors.New("exec: curl: exit status 28: Connection timed out")
		}
		return "", nil
	}
	probes := MeasureClientPath(context.Background(), fullTargets(), run)
	if ClientPathOK(probes) {
		t.Fatal("a failed probe was reported as a healthy path")
	}
	var failed ClientPathProbe
	for _, p := range probes {
		if !p.OK {
			failed = p
		}
	}
	if failed.Name != "tcp/443" {
		t.Errorf("the failing probe is named %q, want tcp/443", failed.Name)
	}
	if !strings.Contains(failed.Why, "timed out") {
		t.Errorf("the failure does not say why: %q", failed.Why)
	}
}

// One provider having a bad hour is not evidence about this node. Each probe has
// a second target, and reaching either one is enough.
func TestClientPathSurvivesOneUnreachableProvider(t *testing.T) {
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "cp.cloudflare.com") || strings.Contains(joined, "1.1.1.1") {
			return "", errors.New("exit status 28: Connection timed out")
		}
		return "", nil
	}
	probes := MeasureClientPath(context.Background(), fullTargets(), run)
	if !ClientPathOK(probes) {
		t.Fatalf("one provider being down reverted a healthy migration: %+v", probes)
	}
}

// An exit that is draining or refusing ICMP must not spend one of the migration's
// three attempts: those probes are recorded, not decisive.
func TestExitReachabilityIsRecordedButNotDecisive(t *testing.T) {
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "203.0.113.7") || strings.Contains(joined, "198.51.100.9") {
			return "", errors.New("exit status 1: 100% packet loss")
		}
		return "", nil
	}
	probes := MeasureClientPath(context.Background(), fullTargets(), run)
	if !ClientPathOK(probes) {
		t.Fatal("an unreachable exit reverted the migration on its own")
	}
	var found bool
	for _, p := range probes {
		if p.Name == "icmp/direct" {
			found = true
			if p.OK {
				t.Error("the failure was smoothed over instead of recorded")
			}
			if p.Decisive {
				t.Error("a third party's uptime was made decisive")
			}
		}
	}
	if !found {
		t.Error("the direct probe was not recorded at all")
	}
}

// The management address is this host's own: when it stops answering through the
// tunnel, THIS node broke, and that is exactly what the revert is for.
func TestMgmtProbeIsDecisive(t *testing.T) {
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "172.29.3.10") {
			return "", errors.New("exit status 1: 100% packet loss")
		}
		return "", nil
	}
	probes := MeasureClientPath(context.Background(), fullTargets(), run)
	if ClientPathOK(probes) {
		t.Fatal("client traffic to the mgmt overlay is dead and the migration stands")
	}
}

// Measuring NOTHING is not the same as measuring success. A prober that could not
// run must not vouch for the path — that is the false confidence this whole
// feature exists to remove.
func TestNoProbesIsNotHealthy(t *testing.T) {
	if ClientPathOK(nil) {
		t.Error("an empty probe set reported the client path healthy")
	}
	// Nor may a set of purely informational probes: nothing decisive was measured.
	if ClientPathOK([]ClientPathProbe{{Name: "icmp/direct", OK: true}}) {
		t.Error("informational probes alone vouched for the client path")
	}
}

// Without a gateway the probes cannot be told apart from an upstream failure, so
// nothing is reported rather than something ambiguous.
func TestNoGatewayMeasuresNothing(t *testing.T) {
	if got := MeasureClientPath(context.Background(), ClientPathTargets{}, func(context.Context, string, ...string) (string, error) {
		t.Fatal("probed without a gateway to compare against")
		return "", nil
	}); len(got) != 0 {
		t.Errorf("measured %d probes with no gateway", len(got))
	}
}

// The readiness gate carried a reachability check that was never given a target,
// so "ready" meant "DNS resolves" — and DNS resolves in the HOST namespace, which
// the migration does not touch. The gate could pass on a namespace with no path
// out at all.
func TestExitProbeTargetPicksALiveLiteralEndpoint(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{
		{Name: "drained", Endpoint: "203.0.113.1:443", Drained: true},
		{Name: "hostname", Endpoint: "exit.example.com:443"},
		{Name: "good", Endpoint: "198.51.100.9:51820"},
	}}}
	host, port := exitProbeTarget(spec)
	if host != "198.51.100.9" || port != 51820 {
		t.Fatalf("got %s:%d, want the first live literal endpoint", host, port)
	}
}

// No usable endpoint means no target, not a bogus one: netns.Ready then skips the
// check rather than failing a healthy namespace over an unparseable address.
func TestExitProbeTargetIsEmptyWhenNothingIsDialable(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{ExitTunnels: []domain.ExitTunnel{
		{Name: "hostname", Endpoint: "exit.example.com:443"},
		{Name: "junk", Endpoint: "not-an-endpoint"},
	}}}
	if host, port := exitProbeTarget(spec); host != "" || port != 0 {
		t.Fatalf("got %s:%d, want no target", host, port)
	}
}
