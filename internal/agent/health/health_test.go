package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

func passing(detail string) Probe {
	return func(context.Context) Result { return ok(detail, 5*time.Millisecond) }
}

func failing(detail string) Probe {
	return func(context.Context) Result { return fail(detail) }
}

func TestEvaluateReady(t *testing.T) {
	state, checks := Evaluate(context.Background(), nil, []Check{
		{Name: "a", Probe: passing("ok-a")},
		{Name: "b", Probe: passing("ok-b")},
	})
	if state != domain.StateReady {
		t.Fatalf("state = %q, want Ready", state)
	}
	if len(checks) != 2 || !checks[0].OK || checks[0].Detail != "ok-a" {
		t.Errorf("checks = %+v", checks)
	}
}

func TestEvaluateDegraded(t *testing.T) {
	state, checks := Evaluate(context.Background(), nil, []Check{
		{Name: "a", Probe: passing("ok")},
		{Name: "b", Probe: failing("boom")},
	})
	if state != domain.StateDegraded {
		t.Fatalf("state = %q, want Degraded", state)
	}
	// All check results are reported, not just the failing one.
	if len(checks) != 2 {
		t.Fatalf("want 2 checks, got %d", len(checks))
	}
	if checks[1].OK || checks[1].Detail != "boom" {
		t.Errorf("failing check = %+v", checks[1])
	}
}

func TestEvaluateReconcileError(t *testing.T) {
	// A reconcile error short-circuits to Error and does not run the probes.
	ran := false
	probe := func(context.Context) Result { ran = true; return ok("", 0) }
	state, checks := Evaluate(context.Background(), errors.New("nft failed"), []Check{{Name: "x", Probe: probe}})
	if state != domain.StateError {
		t.Fatalf("state = %q, want Error", state)
	}
	if ran {
		t.Error("probes must not run when reconcile failed")
	}
	if len(checks) != 1 || checks[0].Name != "reconcile" || checks[0].OK {
		t.Errorf("expected synthetic failing reconcile check, got %+v", checks)
	}
}

func TestEvaluateNoChecks(t *testing.T) {
	state, checks := Evaluate(context.Background(), nil, nil)
	if state != domain.StateReconciling {
		t.Errorf("state = %q, want Reconciling when nothing to check", state)
	}
	if checks != nil {
		t.Errorf("expected nil checks, got %+v", checks)
	}
}

func TestExitChecksRespectSpec(t *testing.T) {
	probes := ExitProbes{
		HandshakeFresh: passing("hs"),
		WARPEgress:     passing("warp"),
		DNSResolves:    passing("dns"),
	}
	// WARP egress + DNS enabled ⇒ all three checks.
	warpSpec := domain.NodeSpec{Role: domain.RoleExit, Egress: domain.EgressWARP, DNS: domain.DNSFilterSpec{Enabled: true}}
	if names := checkNames(ExitChecks(warpSpec, probes)); len(names) != 3 {
		t.Errorf("warp+dns exit: want 3 checks, got %v", names)
	}

	// Direct egress, DNS off ⇒ only handshake.
	directSpec := domain.NodeSpec{Role: domain.RoleExit, Egress: domain.EgressDirect}
	names := checkNames(ExitChecks(directSpec, probes))
	if len(names) != 1 || names[0] != "wg-handshake" {
		t.Errorf("direct exit: want [wg-handshake], got %v", names)
	}
}

func TestMasterChecks(t *testing.T) {
	probes := MasterProbes{MihomoAPI: passing("api"), WGServerUp: passing("wg")}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{ExternalController: "10.20.25.254:9090"}}
	names := checkNames(MasterChecks(spec, probes))
	if len(names) != 2 {
		t.Fatalf("want 2 master checks, got %v", names)
	}

	// No external controller ⇒ mihomo-api check omitted.
	specNoAPI := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{}}
	if names := checkNames(MasterChecks(specNoAPI, probes)); len(names) != 1 || names[0] != "client-wg" {
		t.Errorf("no-api master: want [client-wg], got %v", names)
	}
}

func TestEndToEndExitReady(t *testing.T) {
	spec := domain.NodeSpec{Role: domain.RoleExit, Egress: domain.EgressWARP, DNS: domain.DNSFilterSpec{Enabled: true}}
	checks := ExitChecks(spec, ExitProbes{
		HandshakeFresh: passing("12s"),
		WARPEgress:     passing("104.16.0.1"),
		DNSResolves:    passing("ok"),
	})
	state, results := Evaluate(context.Background(), nil, checks)
	if state != domain.StateReady || len(results) != 3 {
		t.Fatalf("state=%q results=%d", state, len(results))
	}
}

func checkNames(checks []Check) []string {
	out := make([]string, len(checks))
	for i, c := range checks {
		out[i] = c.Name
	}
	return out
}

func TestNewestHandshake(t *testing.T) {
	out := "PUBKEY1\t1700000000\nPUBKEY2\t1700000123\nPUBKEY3\t0\n"
	if got := newestHandshake(out); got != 1700000123 {
		t.Errorf("newestHandshake = %d, want 1700000123", got)
	}
	if got := newestHandshake(""); got != 0 {
		t.Errorf("empty newestHandshake = %d, want 0", got)
	}
	if got := newestHandshake("garbage line\n"); got != 0 {
		t.Errorf("garbage newestHandshake = %d, want 0", got)
	}
}

func TestHostOf(t *testing.T) {
	if got := hostOf("10.20.0.5:53"); got != "10.20.0.5" {
		t.Errorf("hostOf = %q", got)
	}
	if got := hostOf(""); got != "" {
		t.Errorf("hostOf empty = %q", got)
	}
}
