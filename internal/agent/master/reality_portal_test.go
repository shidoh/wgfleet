package master

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/xray"
)

func portalSpec(t *testing.T) domain.NodeSpec {
	t.Helper()
	spec, _ := masterSpec(t)
	spec.Master.RealityPortal = &domain.RealityPortalSpec{
		ListenPort: 48123, SocksPort: domain.RealityPortalSocksPort,
		ServerName: "www.python.org", Dest: "www.python.org:443", Image: "ghcr.io/xtls/xray-core:26.6.22",
		Clients: []domain.RealityPortalClient{{Exit: "exit-de-1", UUID: "11111111-0000-4000-8000-000000000001", ShortID: "0a0b"}},
	}
	return spec
}

type portalRig struct {
	p     realityPortalPlanner
	paths Paths
	up    bool
	addrs map[string]bool
}

func newPortalRig(t *testing.T) *portalRig {
	t.Helper()
	r := &portalRig{paths: testPaths(t), addrs: map[string]bool{"127.0.0.1": true}}
	priv, _, err := xray.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	r.p = realityPortalPlanner{
		configPath:    r.paths.RealityPortal,
		composePath:   r.paths.RealityPortalYML,
		privateKey:    priv,
		up:            func(string) bool { return r.up },
		netnsAttached: func() bool { return false },
		addrExists:    func(ip string) bool { return r.addrs[ip] },
	}
	return r
}

func (r *portalRig) plan(t *testing.T, spec domain.NodeSpec) []reconcile.Action {
	t.Helper()
	acts, err := r.p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return acts
}

func onlyNoChange(acts []reconcile.Action) bool {
	return len(acts) == 1 && !acts[0].Changes()
}

func TestRealityPortalPlannerDownWhenNotInSpec(t *testing.T) {
	r := newPortalRig(t)
	spec, _ := masterSpec(t)
	if acts := r.plan(t, spec); !onlyNoChange(acts) {
		t.Fatalf("no portal, nothing running: %+v", acts)
	}
	// A portal the spec no longer has is stopped — also the one a rolled-back
	// agent left behind.
	r.up = true
	if acts := r.plan(t, spec); !hasExecContaining(acts, "down") {
		t.Fatalf("no portal but xray-portal up: %+v", acts)
	}
}

func TestRealityPortalPlannerPendingWithoutKey(t *testing.T) {
	r := newPortalRig(t)
	r.p.privateKey = ""
	if acts := r.plan(t, portalSpec(t)); !onlyNoChange(acts) || !strings.Contains(acts[0].Summary+acts[0].Display, "key") {
		t.Fatalf("no key: %+v", acts)
	}
}

// One bad field keeps the last-good portal serving instead of failing the pass.
func TestRealityPortalPlannerKeepsLastGoodOnInvalidSpec(t *testing.T) {
	r := newPortalRig(t)
	spec := portalSpec(t)
	spec.Master.RealityPortal.Dest = ""
	if acts := r.plan(t, spec); !onlyNoChange(acts) {
		t.Fatalf("invalid spec: %+v", acts)
	}
}

// At boot the namespace link may not exist yet: binding SOCKS there would fail
// and crash-loop xray. The planner waits for the address instead.
func TestRealityPortalPlannerWaitsForTheSocksAddress(t *testing.T) {
	r := newPortalRig(t)
	r.p.netnsAttached = func() bool { return true }
	if acts := r.plan(t, portalSpec(t)); !onlyNoChange(acts) {
		t.Fatalf("address absent: %+v", acts)
	}
	r.addrs["100.127.255.1"] = true
	if acts := r.plan(t, portalSpec(t)); !hasExecContaining(acts, "up", "-d") {
		t.Fatalf("address present: %+v", acts)
	}
}

func TestRealityPortalPlannerRendersAndStarts(t *testing.T) {
	r := newPortalRig(t)
	acts := r.plan(t, portalSpec(t))
	var cfg, yml *reconcile.Action
	for i := range acts {
		switch acts[i].Target {
		case r.paths.RealityPortal:
			cfg = &acts[i]
		case r.paths.RealityPortalYML:
			yml = &acts[i]
		}
	}
	if cfg == nil || yml == nil {
		t.Fatalf("missing file actions: %+v", acts)
	}
	if !strings.Contains(yml.Display, "container_name: xray-portal") || !strings.Contains(yml.Display, `restart: "no"`) {
		t.Errorf("compose:\n%s", yml.Display)
	}
	if strings.Contains(cfg.Display, r.p.privateKey) || strings.Contains(cfg.Display, PortalSocksPassword(r.p.privateKey, "exit-de-1")) {
		t.Errorf("plan output leaks a secret:\n%s", cfg.Display)
	}
	if !strings.Contains(cfg.Display, `"listen": "127.0.0.1"`) {
		t.Errorf("SOCKS not on the loopback with mihomo on the host:\n%s", cfg.Display)
	}
	if !hasExecContaining(acts, "up", "-d") {
		t.Errorf("not started: %+v", acts)
	}
	applyFiles(t, r.p, portalSpec(t))
	fi, err := os.Stat(r.paths.RealityPortal)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode = %v, %v; want 0600", fi.Mode(), err)
	}
	// Converged and running: nothing to do.
	r.up = true
	for _, a := range r.plan(t, portalSpec(t)) {
		if a.Changes() {
			t.Errorf("converged portal still changes: %+v", a)
		}
	}
	// A new exit changes the config: restart, not re-create.
	spec := portalSpec(t)
	spec.Master.RealityPortal.Clients = append(spec.Master.RealityPortal.Clients,
		domain.RealityPortalClient{Exit: "exit-2", UUID: "22222222-0000-4000-8000-000000000002", ShortID: "0c0d"})
	if acts := r.plan(t, spec); !hasExecContaining(acts, "restart", "xray") {
		t.Errorf("config change without a restart: %+v", acts)
	}
}

func TestPortalSocksAddrFollowsAttach(t *testing.T) {
	spec := portalSpec(t)
	if got := PortalSocksAddr(spec, false); got != "127.0.0.1" {
		t.Errorf("host mode: %q, want the loopback", got)
	}
	if got := PortalSocksAddr(spec, true); got != NetnsHostIP(spec) || got == "" {
		t.Errorf("netns mode: %q, want the host end of the link %q", got, NetnsHostIP(spec))
	}
}

// Both consumers on the master — the portal and mihomo — derive the same
// password per exit, and different exits never share one.
func TestPortalSocksCredsDeterministicPerExit(t *testing.T) {
	a1 := PortalSocksPassword("key-a", "exit-1")
	if a1 != PortalSocksPassword("key-a", "exit-1") || len(a1) != 32 {
		t.Fatalf("password %q not stable or not 32 chars", a1)
	}
	if a1 == PortalSocksPassword("key-a", "exit-2") || a1 == PortalSocksPassword("key-b", "exit-1") {
		t.Error("passwords collide across exits or keys")
	}
}

// filesOnly runs a planner's file actions and drops its commands, so a test can
// converge the files on disk without docker.
type filesOnly struct{ inner reconcile.Planner }

func (f filesOnly) Component() string { return f.inner.Component() }

func (f filesOnly) Plan(ctx context.Context, spec domain.NodeSpec) ([]reconcile.Action, error) {
	acts, err := f.inner.Plan(ctx, spec)
	var out []reconcile.Action
	for _, a := range acts {
		if a.Kind != reconcile.ActionExec {
			out = append(out, a)
		}
	}
	return out, err
}

func applyFiles(t *testing.T, p reconcile.Planner, spec domain.NodeSpec) {
	t.Helper()
	if _, err := reconcile.NewEngine(nil, filesOnly{p}).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
}
