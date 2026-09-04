package master

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Every probe must run INSIDE the prober's namespace. One that ran on the host
// would measure the host's own connectivity — which was fine throughout the
// outage — and report the client path healthy while it was dead.
func TestClientPathProbesRunInsideTheProberNamespace(t *testing.T) {
	var calls []string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	probes := MeasureClientPath(context.Background(), "10.80.0.1", run)
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

// A failing probe must name what failed, and it must not be smoothed over.
func TestClientPathReportsWhichProbeFailed(t *testing.T) {
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "curl") {
			return "", errors.New("exec: curl: exit status 28: Connection timed out")
		}
		return "", nil
	}
	probes := MeasureClientPath(context.Background(), "10.80.0.1", run)
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

// Measuring NOTHING is not the same as measuring success. A prober that could not
// run must not vouch for the path — that is the false confidence this whole
// feature exists to remove.
func TestNoProbesIsNotHealthy(t *testing.T) {
	if ClientPathOK(nil) {
		t.Error("an empty probe set reported the client path healthy")
	}
}

// Without a gateway the probes cannot be told apart from an upstream failure, so
// nothing is reported rather than something ambiguous.
func TestNoGatewayMeasuresNothing(t *testing.T) {
	if got := MeasureClientPath(context.Background(), "", func(context.Context, string, ...string) (string, error) {
		t.Fatal("probed without a gateway to compare against")
		return "", nil
	}); len(got) != 0 {
		t.Errorf("measured %d probes with no gateway", len(got))
	}
}
