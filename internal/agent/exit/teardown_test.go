package exit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
)

func TestExitTeardownPlan(t *testing.T) {
	planners := TeardownPlanners(PathsUnder("/tmp/x"))
	eng := reconcile.NewEngine(nil, planners...)
	report, err := eng.Reconcile(context.Background(), domain.NodeSpec{Decommission: true, Role: domain.RoleExit}, reconcile.ModePlan)
	if err != nil {
		t.Fatal(err)
	}
	out := report.String()
	for _, want := range []string{
		"exit teardown", "awg-quick down", "wg-quick down", "ip route flush table 51820",
		"nft delete table inet wgfleet", "docker compose -f /tmp/x/blocky/docker-compose.yml down", "conntrack -F",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("teardown plan missing %q:\n%s", want, out)
		}
	}
}

func TestExitTeardownWipesFiles(t *testing.T) {
	dir := t.TempDir()
	paths := PathsUnder(dir)

	// Create the managed files so the wipe has something to remove.
	managed := []string{paths.WGConf, paths.WGKey, paths.NFT, paths.RoutingState, paths.DNS}
	for _, p := range managed {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Apply teardown. The best-effort exec steps (awg-quick down, nft delete, ...)
	// fail on a dev box but must not abort the pass, so the file wipes still run.
	eng := reconcile.NewEngine(nil, TeardownPlanners(paths)...)
	if _, err := eng.Reconcile(context.Background(),
		domain.NodeSpec{Decommission: true, Role: domain.RoleExit}, reconcile.ModeApply); err != nil {
		t.Fatalf("teardown apply aborted: %v", err)
	}

	for _, p := range managed {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("teardown did not wipe %s (err=%v)", p, err)
		}
	}
}
