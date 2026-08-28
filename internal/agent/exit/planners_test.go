package exit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/asnfeed"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/dnsfilter"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/egress"
	"github.com/shidoh/wgfleet/internal/wg"
	"github.com/shidoh/wgfleet/internal/xray"
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
		ASBlacklist:  filepath.Join(dir, "as-blacklist.lst"),
	}
}

func TestFirewallReloadGate(t *testing.T) {
	paths := testPaths(t)
	spec, _ := exitSpec(t)

	loaded := false
	pl := firewallPlanner{path: paths.NFT, loaded: func() bool { return loaded }}

	// First apply writes the ruleset file (the nft exec fails on a dev box, but the
	// FileAction runs first).
	eng := reconcile.NewEngine(nil, pl)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	if _, err := os.Stat(paths.NFT); err != nil {
		t.Fatalf("firewall ruleset not written: %v", err)
	}

	// File unchanged + kernel table MISSING ⇒ reload.
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "reload firewall") {
		t.Errorf("expected a reload action when the kernel table is missing, got %+v", acts)
	}

	// File unchanged + kernel table PRESENT ⇒ no change.
	loaded = true
	acts2, _ := pl.Plan(context.Background(), spec)
	for _, a := range acts2 {
		if a.Changes() {
			t.Errorf("expected no-change when the kernel reflects the ruleset, got %+v", acts2)
		}
	}
}

func TestExitFirewallMarksWGRepliesOnEgress(t *testing.T) {
	spec, _ := exitSpec(t) // Routing.EgressInterface = "wgcf"
	acts, err := firewallPlanner{path: testPaths(t).NFT}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(acts[0].Display, "udp sport 51820 meta mark set") {
		t.Errorf("egress exit firewall must mark WG replies:\n%s", acts[0].Display)
	}

	// Direct egress (no egress interface) ⇒ no mark.
	spec.Routing.EgressInterface = ""
	acts2, _ := firewallPlanner{path: testPaths(t).NFT}.Plan(context.Background(), spec)
	if strings.Contains(acts2[0].Display, "meta mark set") {
		t.Errorf("direct-egress exit must not render a mark rule:\n%s", acts2[0].Display)
	}
}

func TestExitFirewallClampsMSSBothWays(t *testing.T) {
	spec, _ := exitSpec(t) // WGServer.MTU = 1440, WARPMTU unset
	acts, err := firewallPlanner{path: testPaths(t).NFT}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	// WARP unset ⇒ the conservative default WARP MTU (wg.DefaultWARPMTU 1380) binds
	// over the 1440 tunnel MTU ⇒ clamp 1340, bidirectional (no oifname). Guarded
	// (`> N`) so it only lowers, never raises a smaller client MSS.
	if want := "tcp flags syn / syn,rst tcp option maxseg size > 1340 tcp option maxseg size set 1340"; !strings.Contains(acts[0].Display, want) {
		t.Errorf("exit firewall must clamp MSS both ways to %q:\n%s", want, acts[0].Display)
	}

	// A constrained WARP path (WARPMTU < tunnel MTU) binds instead.
	spec.WARPMTU = 1280
	acts2, _ := firewallPlanner{path: testPaths(t).NFT}.Plan(context.Background(), spec)
	if want := "maxseg size > 1240 tcp option maxseg size set 1240"; !strings.Contains(acts2[0].Display, want) { // 1280 - 40
		t.Errorf("constrained WARPMTU must bind the clamp (want %q):\n%s", want, acts2[0].Display)
	}
}

func hasChangingSummary(acts []reconcile.Action, substr string) bool {
	for _, a := range acts {
		if a.Changes() && strings.Contains(a.Summary, substr) {
			return true
		}
	}
	return false
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
		"amneziawg interface", "ListenPort = 51820",
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

// TestDNSPlannerEnsureUpWhenDown verifies the reconcile loop self-heals a crashed
// blocky container: with config and compose files unchanged but the stack down,
// the planner re-issues `up -d`; with the stack up it reports no change.
func TestDNSPlannerEnsureUpWhenDown(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	composePath := filepath.Join(dir, "docker-compose.yml")
	spec := domain.NodeSpec{DNS: domain.DNSFilterSpec{Enabled: true, MgmtAddr: "10.20.0.5"}}

	// Pre-write the exact rendered artifacts so the file actions report no change,
	// isolating the ensure-up branch from a config/compose change.
	cfg, err := dnsfilter.RenderBlocky(spec.DNS)
	if err != nil {
		t.Fatal(err)
	}
	composeYAML, err := compose.RenderBlockyCompose(compose.BlockyInput{Image: spec.DNS.Image, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(composePath, []byte(composeYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	hasUp := func(actions []reconcile.Action) bool {
		for _, a := range actions {
			if a.Kind == reconcile.ActionExec && strings.Contains(a.Display, "up -d") {
				return true
			}
		}
		return false
	}

	down := dnsPlanner{configPath: cfgPath, composePath: composePath, up: func(string) bool { return false }}
	actions, err := down.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasUp(actions) {
		t.Error("stack down with unchanged config: expected an ensure-up `up -d` action")
	}

	up := dnsPlanner{configPath: cfgPath, composePath: composePath, up: func(string) bool { return true }}
	actions, err = up.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if hasUp(actions) {
		t.Error("stack already up with unchanged config: must not re-issue `up -d`")
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
	// own physical link, so with no override/probe its MTU is wg.DefaultWARPMTU
	// (1380). It must NOT be derived from the 1360 master↔exit tunnel — that nested
	// computation gives 1300, below the client MTU, and fragments egress.
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
	if !strings.Contains(got, "MTU = 1380") {
		t.Errorf("WARP MTU not 1380 (DefaultWARPMTU, sequential model); wgcf.conf:\n%s", got)
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

func TestRoutingFlushesConntrackOnSwitchToDirect(t *testing.T) {
	paths := testPaths(t)
	warp, _ := exitSpec(t) // WARP egress + routing intent

	// Record the WARP routing intent so the state file holds the WARP ruleset.
	eng := reconcile.NewEngine(nil, routingPlanner{statePath: paths.RoutingState})
	_, _ = eng.Reconcile(context.Background(), warp, reconcile.ModeApply)

	// Failover WARP→direct: routing.Render yields no steps, but the transition must
	// flush conntrack once so flows pinned to the now-dead WARP path re-resolve
	// immediately instead of black-holing for the conntrack timeout (an earlier finding, M-3).
	direct := warp
	direct.Egress = domain.EgressDirect
	direct.Routing.EgressInterface = ""
	actions, err := routingPlanner{statePath: paths.RoutingState}.Plan(context.Background(), direct)
	if err != nil {
		t.Fatal(err)
	}
	var sawConntrack bool
	for _, a := range actions {
		if strings.Contains(a.Summary, "conntrack") {
			sawConntrack = true
		}
	}
	if !sawConntrack {
		t.Error("WARP→direct transition must flush conntrack once")
	}

	// Persist the direct marker, then a steady direct pass must NOT re-flush.
	eng2 := reconcile.NewEngine(nil, routingPlanner{statePath: paths.RoutingState})
	_, _ = eng2.Reconcile(context.Background(), direct, reconcile.ModeApply)
	steady, err := routingPlanner{statePath: paths.RoutingState}.Plan(context.Background(), direct)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range steady {
		if strings.Contains(a.Summary, "conntrack") {
			t.Error("steady direct egress must not re-flush conntrack (an earlier finding: on change only)")
		}
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

// (TestExitForwardPlanner moved to internal/agent/dockerfw, where the shared
// ForwardPlanner now lives.)

// --- scanner-ASN blacklist feed ---

func TestASNFeedDisabled(t *testing.T) {
	spec, _ := exitSpec(t)
	spec.Firewall.ASBlacklist = false
	p := asnFeedPlanner{cachePath: testPaths(t).ASBlacklist, interval: time.Hour}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("disabled feed must not change anything, got %+v", acts)
		}
	}
}

func TestASNFeedRefreshesWhenStaleThenFirewallRenders(t *testing.T) {
	spec, _ := exitSpec(t) // ASBlacklist = true
	paths := testPaths(t)
	cacheBytes := asnfeed.EncodeCache([]string{"203.0.113.0/24"}, []string{"2001:db8::/32"}, time.Unix(0, 0))

	var calls int
	p := asnFeedPlanner{
		cachePath: paths.ASBlacklist,
		v4URL:     "http://v4", v6URL: "http://v6",
		interval: time.Hour,
		now:      func() time.Time { return time.Unix(1_000_000, 0) },
		refresh: func(_ context.Context, _, _ string, _ time.Time) ([]byte, error) {
			calls++
			return cacheBytes, nil
		},
	}

	// No cache yet ⇒ a refresh action that changes state.
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "refresh scanner-ASN blacklist") {
		t.Fatalf("expected a refresh action when the cache is absent, got %+v", acts)
	}

	// Apply writes the cache from the injected refresh.
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if calls != 1 {
		t.Errorf("refresh called %d times, want 1", calls)
	}
	if _, err := os.Stat(paths.ASBlacklist); err != nil {
		t.Fatalf("cache not written: %v", err)
	}

	// The firewall planner now renders those elements into the nft sets.
	fwActs, err := firewallPlanner{path: paths.NFT, asBlacklistCache: paths.ASBlacklist}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fwActs[0].Display, "203.0.113.0/24") {
		t.Errorf("firewall must render the cached v4 prefix:\n%s", fwActs[0].Display)
	}
	if !strings.Contains(fwActs[0].Display, "2001:db8::/32") {
		t.Errorf("firewall must render the cached v6 prefix:\n%s", fwActs[0].Display)
	}
}

func TestASNFeedFreshNoChange(t *testing.T) {
	spec, _ := exitSpec(t)
	paths := testPaths(t)
	if err := os.MkdirAll(filepath.Dir(paths.ASBlacklist), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.ASBlacklist, asnfeed.EncodeCache([]string{"1.0.0.0/8"}, nil, time.Now()), 0o644); err != nil {
		t.Fatal(err)
	}
	p := asnFeedPlanner{cachePath: paths.ASBlacklist, interval: time.Hour, now: time.Now}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("a fresh cache must not refresh, got %+v", acts)
		}
	}
}

func TestASNFeedFailureNonFatalAndBacksOff(t *testing.T) {
	spec, _ := exitSpec(t)
	paths := testPaths(t)
	now := time.Unix(2_000_000, 0)
	p := asnFeedPlanner{
		cachePath: paths.ASBlacklist,
		v4URL:     "http://v4", v6URL: "http://v6",
		interval: time.Hour,
		now:      func() time.Time { return now },
		refresh: func(_ context.Context, _, _ string, _ time.Time) ([]byte, error) {
			return nil, errors.New("network down")
		},
	}
	// Apply: the refresh fails but is swallowed (non-fatal), no cache is written, and
	// the attempt marker is touched so the next pass backs off.
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatalf("a failed refresh must be non-fatal, got: %v", err)
	}
	if _, err := os.Stat(paths.ASBlacklist); !os.IsNotExist(err) {
		t.Errorf("cache must not be written on failure (keep last-good)")
	}
	if _, err := os.Stat(paths.ASBlacklist + ".attempt"); err != nil {
		t.Errorf("attempt marker must be written even on failure: %v", err)
	}

	// Within the retry window the next Plan must NOT attempt again.
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("expected backoff (no refresh) within the retry window, got %+v", acts)
		}
	}
}

func TestXrayPlannerDisabledNoop(t *testing.T) {
	dir := t.TempDir()
	p := xrayPlanner{
		configPath:  filepath.Join(dir, "config.json"),
		composePath: filepath.Join(dir, "docker-compose.yml"),
		privateKey:  "PRIV",
	}
	// AWG-only exit (no reality transport): the planner must be a no-op and write
	// nothing.
	acts, err := p.Plan(context.Background(), domain.NodeSpec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Kind == reconcile.ActionExec {
			t.Errorf("disabled xray planner emitted an exec: %q", a.Display)
		}
	}
	if _, err := os.Stat(p.configPath); err == nil {
		t.Error("disabled xray planner wrote a config file")
	}
}

func TestXrayPlannerRendersAndEnsuresUp(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	composePath := filepath.Join(dir, "docker-compose.yml")
	spec := domain.NodeSpec{
		EnabledTransports: []domain.MasterTransport{domain.TransportRealityXHTTP},
		Reality: &domain.RealityServerSpec{
			ListenPort: 8443, UUID: "11111111-2222-3333-4444-555555555555",
			ShortID: "0badc0de", ServerName: "www.microsoft.com", Dest: "www.microsoft.com:443",
			XHTTPPath: "/down",
		},
	}
	hasUp := func(actions []reconcile.Action) bool {
		for _, a := range actions {
			if a.Kind == reconcile.ActionExec && strings.Contains(a.Display, "up -d") {
				return true
			}
		}
		return false
	}

	// First pass: config absent → renders config + compose and brings the stack up.
	p := xrayPlanner{configPath: cfgPath, composePath: composePath, privateKey: "PRIV", up: func(string) bool { return false }}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasUp(acts) {
		t.Error("first render should bring the xray stack up")
	}

	// Pre-write the exact rendered artifacts so a second pass sees unchanged files,
	// isolating the ensure-up branch (mirrors TestDNSPlannerEnsureUpWhenDown).
	cfg, err := xray.RenderConfig(xray.RenderInput{Spec: *spec.Reality, PrivateKey: "PRIV", EgressMark: xray.EgressMark})
	if err != nil {
		t.Fatal(err)
	}
	composeYAML, err := compose.RenderXrayCompose(compose.XrayInput{Image: spec.Reality.Image, ConfigPath: cfgPath, NetAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(composePath, []byte(composeYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	// Stack up + unchanged config ⇒ no re-up.
	up := xrayPlanner{configPath: cfgPath, composePath: composePath, privateKey: "PRIV", up: func(string) bool { return true }}
	acts2, err := up.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if hasUp(acts2) {
		t.Error("unchanged config + stack up: must not re-issue up -d")
	}
}

func TestXrayPlannerStopsWhenTransportRemoved(t *testing.T) {
	dir := t.TempDir()
	awgOnly := domain.NodeSpec{} // no reality transport (default AWG-only)
	hasDown := func(acts []reconcile.Action) bool {
		for _, a := range acts {
			if a.Kind == reconcile.ActionExec && strings.Contains(a.Display, "down") {
				return true
			}
		}
		return false
	}

	// xray still up but reality no longer enabled ⇒ stop it (compose down).
	up := xrayPlanner{configPath: filepath.Join(dir, "c.json"), composePath: filepath.Join(dir, "dc.yml"), up: func(string) bool { return true }}
	acts, err := up.Plan(context.Background(), awgOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !hasDown(acts) {
		t.Error("reality removed while xray up: expected a compose down")
	}

	// Already down ⇒ no-op (no perpetual down every pass).
	down := xrayPlanner{configPath: filepath.Join(dir, "c.json"), composePath: filepath.Join(dir, "dc.yml"), up: func(string) bool { return false }}
	acts2, _ := down.Plan(context.Background(), awgOnly)
	if hasDown(acts2) {
		t.Error("reality removed + xray already down: must not re-issue down")
	}
}

// A reality-only exit must not keep an AWG server interface up. Rendering it
// unconditionally left pn8 carrying awg0 with the master's stale peer, dropping
// TX packets, and holding the pre-ADR-0030 shared key as a trap for re-enablement.
func TestWGPlannerBringsInterfaceDownWhenAWGDisabled(t *testing.T) {
	spec := domain.NodeSpec{
		Role:              domain.RoleExit,
		EnabledTransports: []domain.MasterTransport{domain.TransportRealityXHTTP},
	}
	pl := wgPlanner{path: filepath.Join(t.TempDir(), "awg0.conf"), up: func(string) bool { return true }}
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || !actions[0].Changes() {
		t.Fatalf("expected a single down action, got %+v", actions)
	}
	if !strings.Contains(actions[0].Summary, "disabled") {
		t.Errorf("summary must explain why, got %q", actions[0].Summary)
	}
}

// Idempotent: an already-down interface must not re-run awg-quick down forever.
func TestWGPlannerQuietWhenDisabledAndAlreadyDown(t *testing.T) {
	spec := domain.NodeSpec{
		Role:              domain.RoleExit,
		EnabledTransports: []domain.MasterTransport{domain.TransportRealityXHTTP},
	}
	pl := wgPlanner{path: filepath.Join(t.TempDir(), "awg0.conf"), up: func(string) bool { return false }}
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].Changes() {
		t.Fatalf("an already-down interface must be a no-change, got %+v", actions[0])
	}
}

// The safety asymmetry: an EMPTY transport set means AWG (back-compat), so a spec
// that simply fails to populate the field must never tear down a live interface.
// Bringing an interface down on bad information costs an exit's data plane;
// leaving a stale one up costs dropped packets.
func TestWGPlannerNeverTearsDownOnMissingTransportInfo(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  []domain.MasterTransport
	}{
		{"empty means awg (back-compat)", nil},
		{"awg explicitly enabled", []domain.MasterTransport{domain.TransportAWG}},
		{"dual transport", []domain.MasterTransport{domain.TransportAWG, domain.TransportRealityXHTTP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if awgTransportDisabled(domain.NodeSpec{EnabledTransports: tc.set}) {
				t.Fatal("must not report AWG disabled — teardown would drop a live tunnel")
			}
		})
	}
	if !awgTransportDisabled(domain.NodeSpec{
		EnabledTransports: []domain.MasterTransport{domain.TransportRealityXHTTP},
	}) {
		t.Fatal("an explicit reality-only set must report AWG disabled")
	}
}

// The WARP→direct failover must actually REMOVE the WARP policy routing.
//
// Flushing conntrack was the whole of the transition, and it is the half that does
// nothing on its own: routing.Render returns no steps for a direct-egress intent,
// so `ip rule from <pool> lookup 51820` and `default dev wgcf` stayed in the kernel,
// and warpPlanner keeps wgcf up by design. Every client packet kept being policy-
// routed into the tunnel ADR-0017 had just declared blocked, and the conntrack flush
// merely re-pinned the flows onto the same dead path. TeardownActions existed and
// was reachable only from decommission.
func TestRoutingRemovesWARPRulesOnSwitchToDirect(t *testing.T) {
	paths := testPaths(t)
	warp, _ := exitSpec(t)

	// Only the state file matters here; the sysctl/ip steps cannot run off-Linux.
	eng := reconcile.NewEngine(nil, routingPlanner{statePath: paths.RoutingState})
	_, _ = eng.Reconcile(context.Background(), warp, reconcile.ModeApply)

	direct := warp
	direct.Egress = domain.EgressDirect
	direct.Routing.EgressInterface = ""
	actions, err := routingPlanner{statePath: paths.RoutingState}.Plan(context.Background(), direct)
	if err != nil {
		t.Fatal(err)
	}
	var sawRuleDel, sawTableFlush bool
	for _, a := range actions {
		switch {
		case strings.Contains(a.Display, "ip rule del"):
			sawRuleDel = true
		case strings.Contains(a.Display, "ip route flush table"):
			sawTableFlush = true
		}
	}
	if !sawRuleDel || !sawTableFlush {
		t.Errorf("WARP→direct must delete the egress ip rule and flush the egress table; "+
			"rule_del=%v table_flush=%v\nplan:\n%s", sawRuleDel, sawTableFlush, planDump(actions))
	}

	// And a steady direct pass must not keep re-issuing them.
	eng2 := reconcile.NewEngine(nil, routingPlanner{statePath: paths.RoutingState})
	_, _ = eng2.Reconcile(context.Background(), direct, reconcile.ModeApply)
	steady, err := routingPlanner{statePath: paths.RoutingState}.Plan(context.Background(), direct)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range steady {
		if strings.Contains(a.Display, "ip rule del") {
			t.Errorf("steady direct egress must not re-run the teardown:\n%s", planDump(steady))
		}
	}
}

func planDump(actions []reconcile.Action) string {
	var b strings.Builder
	for _, a := range actions {
		b.WriteString("  " + a.Summary + " | " + a.Display + "\n")
	}
	return b.String()
}
