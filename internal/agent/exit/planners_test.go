package exit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/egress"
	"github.com/shidoh/wgfleet/internal/wg"
)

func testPaths(t *testing.T) Paths {
	t.Helper()
	dir := t.TempDir()
	return Paths{
		WGKey:        filepath.Join(dir, "wg.key"),
		WGConf:       filepath.Join(dir, "awg0.conf"),
		NFT:          filepath.Join(dir, "wgfleet.nft"),
		WGCF:         filepath.Join(dir, "wgcf.conf"),
		DNS:          filepath.Join(dir, "blocky", "config.yml"),
		DNSCompose:   filepath.Join(dir, "blocky", "docker-compose.yml"),
		RoutingState: filepath.Join(dir, "routing.applied"),
	}
}

func exitSpec(t *testing.T) (domain.NodeSpec, string) {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	peerKey, _ := wg.GenerateKeyPair()
	spec := domain.NodeSpec{
		Role:   domain.RoleExit,
		Egress: domain.EgressWARP,
		WGServer: domain.WGServerSpec{
			ListenPort:  51820,
			AddressPool: "10.81.0.0/24",
			Address:     "10.81.0.1",
			MTU:         1440,
		},
		Peers: []domain.PeerSpec{{
			Name:       "master-xa-1",
			PublicKey:  peerKey.PublicKey,
			AllowedIPs: []string{"10.81.0.2/32"},
			Keepalive:  25,
		}},
		DNS:      domain.DNSFilterSpec{Enabled: true, MgmtAddr: "10.20.0.5", Prometheus: true},
		Firewall: domain.FirewallSpec{ASBlacklist: true, Whitelist: []string{"10.20.0.0/16"}, WGPort: 51820},
		Routing:  domain.RoutingSpec{EgressInterface: "wgcf", MasterIP: "203.0.113.1", DirectCIDRs: []string{"10.0.0.0/8"}},
	}
	return spec, kp.PrivateKey
}

func TestExitPlanModeWritesNothing(t *testing.T) {
	paths := testPaths(t)
	spec, priv := exitSpec(t)

	eng := reconcile.NewEngine(nil, Planners(Input{Paths: paths, PrivateKey: priv})...)
	report, err := eng.Reconcile(context.Background(), spec, reconcile.ModePlan)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	// Dry-run must not have created any managed file.
	for _, p := range []string{paths.WGConf, paths.NFT, paths.DNS} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("plan mode wrote %s; dry-run must not mutate", p)
		}
	}

	out := report.String()
	// The rendered artifacts must be visible in the plan.
	for _, want := range []string{
		"firewall (nftables)", "table inet wgfleet",
		"wireguard interface", "ListenPort = 51820",
		"policy routing", "ip rule add to 203.0.113.1 lookup main",
		"warp egress (wgcf)", "wgcf register --accept-tos",
		"dns filter (blocky)", "10.20.0.5:53", "image: spx01/blocky",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output missing %q\n---\n%s", want, out)
		}
	}
	// Secrets must never appear in plan output.
	if strings.Contains(out, priv) {
		t.Error("plan output leaked the WG private key")
	}
}

func TestExitApplyModeWritesConfigs(t *testing.T) {
	paths := testPaths(t)
	spec, priv := exitSpec(t)

	// Isolate the WG planner: its FileAction writes the config before the
	// awg-quick exec (which fails on a dev box without the tool). Other planners
	// are exercised in the plan-mode test; here we only assert the WG file write.
	eng := reconcile.NewEngine(nil, wgPlanner{path: paths.WGConf, privateKey: priv})
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	// The WG config file should exist with redactable real content.
	data, err := os.ReadFile(paths.WGConf)
	if err != nil {
		t.Fatalf("wg config not written: %v", err)
	}
	if !strings.Contains(string(data), priv) {
		t.Error("applied WG config should contain the real private key")
	}
	info, _ := os.Stat(paths.WGConf)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("wg config perm = %o, want 600", info.Mode().Perm())
	}
}

func TestWARPMTUIsPhysicalNotNested(t *testing.T) {
	// Regression for the sequential MTU model (ADR-0014): WARP rides the exit's
	// own physical link, so its MTU is 1500-60 = 1440 (vanilla WG). It must NOT be
	// derived from the 1360 master↔exit tunnel — that nested computation gives 1300,
	// below the 1360 client MTU, and fragments every egress packet.
	paths := testPaths(t)
	spec, priv := exitSpec(t)
	warp := &egress.WARPConfig{
		PrivateKey:    priv, // any plausible key; redacted in plan, real in apply
		Address4:      "172.16.0.2/32",
		PeerPublicKey: "Y2xvdWRmbGFyZS13YXJwLXB1YmtleS1iYXNlNjQ9",
		// MTU left 0 so the planner computes it from the sequential model.
	}

	// Isolate the WARP planner in apply mode: its FileAction writes wgcf.conf
	// before the wg-quick exec (which fails on a dev box). wgcf.conf holds only the
	// WARP interface, so the MTU assertion can't be satisfied by another config.
	eng := reconcile.NewEngine(nil, warpPlanner{path: paths.WGCF, warp: warp})
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)

	data, err := os.ReadFile(paths.WGCF)
	if err != nil {
		t.Fatalf("wgcf config not written: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "MTU = 1440") {
		t.Errorf("WARP MTU not 1440 (sequential model); wgcf.conf:\n%s", got)
	}
	if strings.Contains(got, "MTU = 1300") {
		t.Errorf("WARP MTU regressed to nested 1300 (would fragment egress); wgcf.conf:\n%s", got)
	}
}

func TestWARPMTUFollowsSpecOverride(t *testing.T) {
	// When the controller pins a constrained WARP MTU (spec.WARPMTU), the WARP
	// planner must use it verbatim rather than the computed 1440 (ADR-0014 / earlier findings
	// : real WARP paths land in 1320-1420).
	paths := testPaths(t)
	spec, priv := exitSpec(t)
	spec.WARPMTU = 1340
	warp := &egress.WARPConfig{
		PrivateKey:    priv,
		Address4:      "172.16.0.2/32",
		PeerPublicKey: "Y2xvdWRmbGFyZS13YXJwLXB1YmtleS1iYXNlNjQ9",
	}
	eng := reconcile.NewEngine(nil, warpPlanner{path: paths.WGCF, warp: warp})
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)

	data, err := os.ReadFile(paths.WGCF)
	if err != nil {
		t.Fatalf("wgcf config not written: %v", err)
	}
	if got := string(data); !strings.Contains(got, "MTU = 1340") {
		t.Errorf("WARP MTU should follow spec.WARPMTU=1340; wgcf.conf:\n%s", got)
	}
}

func TestWGInterfaceEnsureUpWhenDown(t *testing.T) {
	paths := testPaths(t)
	spec, priv := exitSpec(t)

	// Write the config once (apply; the awg-quick exec fails on a dev box but the
	// FileAction runs first), so on the next plan the config is unchanged.
	eng := reconcile.NewEngine(nil, wgPlanner{path: paths.WGConf, privateKey: priv, up: func(string) bool { return false }})
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)

	hasUp := func(actions []reconcile.Action) bool {
		for _, a := range actions {
			if a.Changes() && strings.Contains(a.Display, "awg-quick up") {
				return true
			}
		}
		return false
	}

	// Config unchanged but interface DOWN → must still bring it up.
	down := wgPlanner{path: paths.WGConf, privateKey: priv, up: func(string) bool { return false }}
	a1, _ := down.Plan(context.Background(), spec)
	if !hasUp(a1) {
		t.Error("interface down + unchanged config must emit `awg-quick up`")
	}

	// Config unchanged and interface UP → no change at all (drift-safe).
	up := wgPlanner{path: paths.WGConf, privateKey: priv, up: func(string) bool { return true }}
	a2, _ := up.Plan(context.Background(), spec)
	for _, a := range a2 {
		if a.Changes() {
			t.Errorf("interface up + unchanged config must be no-change, got %s %q", a.Kind, a.Target)
		}
	}
}

func TestRoutingIdempotentAfterApply(t *testing.T) {
	paths := testPaths(t)
	spec, _ := exitSpec(t) // WARP egress + routing intent

	// First apply: the state FileAction writes routing.applied before the exec
	// steps (which fail on a dev box and abort the pass). The intent is recorded.
	eng := reconcile.NewEngine(nil, routingPlanner{statePath: paths.RoutingState})
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	if _, err := os.Stat(paths.RoutingState); err != nil {
		t.Fatalf("routing state file should be written on first apply: %v", err)
	}

	// Second plan, unchanged intent: no routing command re-runs. In particular
	// `conntrack -D` must NOT reappear — an earlier finding flushes on change, not per pass.
	// Stub the kernel probe as healthy so this isolates the state-file gate from
	// live-kernel drift repair (which has its own test).
	healthy := func(domain.RoutingSpec) bool { return true }
	actions, err := routingPlanner{statePath: paths.RoutingState, applied: healthy}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range actions {
		if a.Changes() {
			t.Errorf("steady routing should be no-change, got %s %s", a.Kind, a.Target)
		}
		if strings.Contains(a.Summary, "conntrack") {
			t.Error("conntrack flush re-emitted on unchanged intent (an earlier finding violation)")
		}
	}

	// Changing the intent re-emits the full step set, including the conntrack flush.
	spec.Routing.MasterIP = "203.0.113.9"
	actions, err = routingPlanner{statePath: paths.RoutingState}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var sawConntrack, sawChange bool
	for _, a := range actions {
		if a.Changes() {
			sawChange = true
		}
		if strings.Contains(a.Summary, "conntrack") && a.Changes() {
			sawConntrack = true
		}
	}
	if !sawChange || !sawConntrack {
		t.Errorf("changed intent must re-run routing incl conntrack flush; change=%v conntrack=%v", sawChange, sawConntrack)
	}
}

func TestRoutingRepairsLiveKernelDrift(t *testing.T) {
	paths := testPaths(t)
	spec, _ := exitSpec(t) // WARP egress + routing intent

	// Record the intent so the state-file gate sees no change on later plans.
	rec := func(applied func(domain.RoutingSpec) bool) routingPlanner {
		return routingPlanner{statePath: paths.RoutingState, applied: applied}
	}
	eng := reconcile.NewEngine(nil, rec(func(domain.RoutingSpec) bool { return true }))
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	if _, err := os.Stat(paths.RoutingState); err != nil {
		t.Fatalf("routing state file should be written on first apply: %v", err)
	}

	// Healthy kernel + unchanged intent ⇒ steady no-change.
	actions, err := rec(func(domain.RoutingSpec) bool { return true }).Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range actions {
		if a.Changes() {
			t.Errorf("healthy kernel must be no-change, got %s %s", a.Kind, a.Summary)
		}
	}

	// Kernel drifted (rules flushed/edited by hand) while the intent and its state
	// file are unchanged ⇒ re-apply the full idempotent set, conntrack flush and
	// egress rule included.
	actions, err = rec(func(domain.RoutingSpec) bool { return false }).Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var changes int
	var sawConntrack, sawEgressRule bool
	for _, a := range actions {
		if a.Changes() {
			changes++
		}
		if a.Changes() && strings.Contains(a.Summary, "conntrack") {
			sawConntrack = true
		}
		if a.Changes() && strings.Contains(a.Summary, "egress table") {
			sawEgressRule = true
		}
	}
	if changes == 0 || !sawConntrack || !sawEgressRule {
		t.Errorf("live-kernel drift must re-apply full set; changes=%d conntrack=%v egress=%v",
			changes, sawConntrack, sawEgressRule)
	}
}

func TestExitSecondPlanIsNoChange(t *testing.T) {
	paths := testPaths(t)
	spec, priv := exitSpec(t)

	// Apply once via the engine. Exec actions (nft -f) fail on a dev box and
	// abort the pass, but the firewall FileAction runs first and writes the file.
	eng := reconcile.NewEngine(nil, Planners(Input{Paths: paths, PrivateKey: priv})...)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)

	if _, err := os.Stat(paths.NFT); err != nil {
		t.Fatalf("firewall file should have been written before exec failure: %v", err)
	}

	// Re-plan the firewall: the file now matches, so its action is no-change.
	actions, err := firewallPlanner{path: paths.NFT}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Kind != reconcile.ActionNoChange {
		t.Errorf("expected no-change on second plan, got %s", actions[0].Kind)
	}
}
