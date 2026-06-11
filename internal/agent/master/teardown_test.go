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
