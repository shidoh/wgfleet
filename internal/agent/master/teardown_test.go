package master

import (
	"context"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

func TestMasterTeardownPlan(t *testing.T) {
	eng := reconcile.NewEngine(nil, TeardownPlanners(PathsUnder("/tmp/x"))...)
	report, err := eng.Reconcile(context.Background(), domain.NodeSpec{Decommission: true, Role: domain.RoleMaster}, reconcile.ModePlan)
	if err != nil {
		t.Fatal(err)
	}
	out := report.String()
	for _, want := range []string{"master teardown", "docker compose", "down", "nft delete table ip wgfleet_master"} {
		if !strings.Contains(out, want) {
			t.Errorf("master teardown plan missing %q:\n%s", want, out)
		}
	}
}

// TestMasterTeardownWipesClientVLESS guards the client-facing VLESS transport
// (ADR-0031): on decommission the xray inbound must be stopped and its config
// (which holds the REALITY private key AND every issued client UUID) plus its
// compose file and the on-node private key must be wiped. Without this the
// container keeps serving valid credentials past "decommission complete".
func TestMasterTeardownWipesClientVLESS(t *testing.T) {
	eng := reconcile.NewEngine(nil, TeardownPlanners(PathsUnder("/tmp/x"))...)
	report, err := eng.Reconcile(context.Background(), domain.NodeSpec{Decommission: true, Role: domain.RoleMaster}, reconcile.ModePlan)
	if err != nil {
		t.Fatal(err)
	}
	out := report.String()
	for _, want := range []string{
		"client-vless/docker-compose.yml", // stack brought down + compose wiped
		"client-vless/config.json",        // config wiped (REALITY key + client UUIDs)
		"client-vless.key",                // on-node REALITY private key wiped
	} {
		if !strings.Contains(out, want) {
			t.Errorf("master teardown plan missing client-vless teardown of %q:\n%s", want, out)
		}
	}
}
