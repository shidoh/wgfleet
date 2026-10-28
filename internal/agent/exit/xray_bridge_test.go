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

func bridgeExitSpec() domain.NodeSpec {
	return domain.NodeSpec{
		EnabledTransports: []domain.MasterTransport{domain.TransportAWG, domain.TransportRealityXHTTP},
		Reality: &domain.RealityServerSpec{Image: "ghcr.io/xtls/xray-core:26.6.22", Bridge: &domain.RealityBridgeSpec{
			Portals: []domain.RealityPortalPeer{{
				Master: "xa-1", Address: "203.0.113.1:48123", PublicKey: "pk", UUID: "u1",
				ShortID: "0a0b", ServerName: "www.python.org",
			}},
		}},
	}
}

func bridgePlanner(t *testing.T, up bool) xrayPlanner {
	t.Helper()
	dir := t.TempDir()
	return xrayPlanner{
		configPath:  filepath.Join(dir, "config.json"),
		composePath: filepath.Join(dir, "docker-compose.yml"),
		up:          func(string) bool { return up },
	}
}

func displayOf(acts []reconcile.Action, target string) string {
	for _, a := range acts {
		if a.Target == target {
			return a.Display
		}
	}
	return ""
}

// The bridge dials out and listens on nothing: no REALITY key is needed, no
// privileged port either — only NET_ADMIN for the egress mark.
func TestXrayPlannerRendersTheBridgeWithoutAKey(t *testing.T) {
	p := bridgePlanner(t, false)
	acts, err := p.Plan(context.Background(), bridgeExitSpec())
	if err != nil {
		t.Fatal(err)
	}
	cfg := displayOf(acts, p.configPath)
	if !strings.Contains(cfg, `"reverse"`) || strings.Contains(cfg, `"inbounds"`) {
		t.Errorf("bridge config:\n%s", cfg)
	}
	yml := displayOf(acts, p.composePath)
	if strings.Contains(yml, "NET_BIND_SERVICE") || !strings.Contains(yml, "NET_ADMIN") {
		t.Errorf("bridge compose capabilities:\n%s", yml)
	}
	if !hasExec(acts, "up -d") {
		t.Errorf("bridge not started: %+v", acts)
	}
}

// With no master ready there is nothing to dial; xray is stopped rather than
// left listening, which is the flow the filter kills.
func TestXrayPlannerStopsTheBridgeWithNoPortals(t *testing.T) {
	spec := bridgeExitSpec()
	spec.Reality.Bridge.Portals = nil
	acts, err := bridgePlanner(t, true).Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasExec(acts, "down") {
		t.Errorf("bridge with no portal left running: %+v", acts)
	}
	acts, err = bridgePlanner(t, false).Plan(context.Background(), spec)
	if err != nil || len(acts) != 1 || acts[0].Changes() {
		t.Errorf("bridge with no portal, already down: %+v %v", acts, err)
	}
}

// A bad portal entry keeps the last-good bridge rather than failing the pass.
func TestXrayPlannerKeepsLastGoodBridgeOnInvalidSpec(t *testing.T) {
	spec := bridgeExitSpec()
	spec.Reality.Bridge.Portals[0].Address = "not-an-address"
	acts, err := bridgePlanner(t, true).Plan(context.Background(), spec)
	if err != nil || len(acts) != 1 || acts[0].Changes() {
		t.Errorf("invalid bridge: %+v %v", acts, err)
	}
}

// Switching an exit between forward and bridge rewrites the config and restarts
// xray; the compose change (capabilities) recreates it.
func TestXrayPlannerSwitchesModeByRecreating(t *testing.T) {
	p := bridgePlanner(t, true)
	p.privateKey = "PRIV"
	fwd := bridgeExitSpec()
	fwd.Reality = &domain.RealityServerSpec{ListenPort: 443, UUID: "u", ShortID: "0a", ServerName: "a", Dest: "a:443", Image: "img"}
	applyFilesForTest(t, p, fwd)
	acts, err := p.Plan(context.Background(), bridgeExitSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !hasExec(acts, "up -d") {
		t.Errorf("forward → bridge did not recreate xray: %+v", acts)
	}
}

type filesOnlyPlanner struct{ inner reconcile.Planner }

func (f filesOnlyPlanner) Component() string { return f.inner.Component() }

func (f filesOnlyPlanner) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	acts, err := f.inner.Plan(ctx, spec)
	var out []reconcile.Action
	for _, a := range acts {
		if a.Kind != reconcile.ActionExec {
			out = append(out, a)
		}
	}
	return out, err
}

func applyFilesForTest(t *testing.T, p reconcile.Planner, spec domain.NodeSpec) {
	t.Helper()
	if _, err := reconcile.NewEngine(nil, filesOnlyPlanner{p}).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	// The dropped commands are modelled as having succeeded, so every compose file
	// written counts as applied (reconcile.ComposeApplied).
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Kind != reconcile.ActionExec && strings.HasSuffix(a.Target, "docker-compose.yml") {
			if b, rerr := os.ReadFile(a.Target); rerr == nil {
				reconcile.MarkComposeAppliedForTest(a.Target, b)
			}
		}
	}
}

// A stopped bridge with a new config is brought up, not restarted: compose
// restart leaves a stopped container stopped.
func TestXrayPlannerStartsAStoppedBridgeOnConfigChange(t *testing.T) {
	p := bridgePlanner(t, false)
	applyFilesForTest(t, p, bridgeExitSpec())
	spec := bridgeExitSpec()
	spec.Reality.Bridge.Portals[0].ServerName = "a.example"
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasExec(acts, "up -d") || hasExec(acts, "restart") {
		t.Errorf("stopped bridge with a new config: %+v", acts)
	}
}

// The xray compose file is current and the container runs — but no `up -d` of
// that file ever succeeded (killed mid-pass, image not pulled), so the running
// container may be the previous image. The planner must apply the file.
func TestXrayPlannerAppliesAComposeFileThatWasNeverApplied(t *testing.T) {
	p := bridgePlanner(t, true)
	applyFilesForTest(t, p, bridgeExitSpec())
	if err := os.Remove(p.composePath + ".applied"); err != nil {
		t.Fatal(err)
	}
	acts, err := p.Plan(context.Background(), bridgeExitSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !hasExec(acts, "up -d") {
		t.Fatalf("an unapplied compose file was reported converged: %+v", acts)
	}
	if hasExec(acts, "restart") {
		t.Errorf("nothing but the compose file is stale, yet the inbound is restarted: %+v", acts)
	}
}
