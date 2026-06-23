package master

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// masterDNSSpec enables the master-tier resolver on the shared masterSpec fixture.
func masterDNSSpec(t *testing.T) domain.NodeSpec {
	t.Helper()
	spec, _ := masterSpec(t) // BindAddress 10.80.0.1
	spec.DNS = domain.DNSFilterSpec{
		Enabled:   true,
		MgmtAddr:  "10.20.25.254",
		Upstreams: []string{"10.20.0.5"}, // the active exit blocky
		Custom: domain.CustomConfig{
			Overrides: map[string]any{
				"conditional": map[string]any{"mapping": map[string]any{"lab.lan": "10.200.99.1"}},
			},
		},
	}
	return spec
}

func TestMasterDNSPlannerRendersClientGatewayBind(t *testing.T) {
	paths := testPaths(t)
	pl := dnsPlanner{
		configPath:   paths.DNS,
		composePath:  paths.DNSCompose,
		up:           func(string) bool { return false }, // stack not up yet
		nonlocalBind: func() bool { return true },        // already set ⇒ no churn
	}
	acts, err := pl.Plan(context.Background(), masterDNSSpec(t))
	if err != nil {
		t.Fatal(err)
	}

	// The rendered config must bind the client-pool gateway (so clients reach the
	// master as their DNS) AND forward to the exit blocky upstream + carry the
	// operator's conditional override.
	var cfg string
	for _, a := range acts {
		if a.Target == paths.DNS {
			cfg = a.Display
		}
	}
	if cfg == "" {
		t.Fatalf("no config action for %s in %+v", paths.DNS, acts)
	}
	for _, want := range []string{"10.80.0.1:53", "10.20.0.5", "lab.lan", "10.200.99.1"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rendered master blocky config missing %q:\n%s", want, cfg)
		}
	}
	// First run: the stack must be brought up.
	if !hasExecContaining(acts, "up", "-d") {
		t.Errorf("expected a bring-up action on first run, got %+v", acts)
	}
}

func TestMasterDNSPlannerDisabled(t *testing.T) {
	spec, _ := masterSpec(t) // DNS left zero ⇒ disabled
	pl := dnsPlanner{configPath: testPaths(t).DNS, composePath: testPaths(t).DNSCompose}
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 1 || acts[0].Changes() {
		t.Fatalf("disabled DNS should be a single no-change, got %+v", acts)
	}
}

func TestMasterDNSPlannerPendingWithoutGateway(t *testing.T) {
	spec := masterDNSSpec(t)
	spec.Master.BindAddress = "" // gateway not resolved yet
	pl := dnsPlanner{configPath: testPaths(t).DNS, composePath: testPaths(t).DNSCompose}
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 1 || acts[0].Changes() {
		t.Fatalf("missing gateway should defer (no-change), got %+v", acts)
	}
}

func hasExecContaining(acts []reconcile.Action, parts ...string) bool {
	for _, a := range acts {
		if a.Kind != reconcile.ActionExec {
			continue
		}
		ok := true
		for _, p := range parts {
			if !strings.Contains(a.Display, p) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
