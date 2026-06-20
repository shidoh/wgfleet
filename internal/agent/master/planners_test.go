package master

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/wg"
	"github.com/shidoh/wgfleet/internal/wgeasy"
)

func testPaths(t *testing.T) Paths {
	t.Helper()
	return PathsUnder(t.TempDir())
}

func masterSpec(t *testing.T) (domain.NodeSpec, string) {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	awg := wg.DeriveAWGParams(wg.TunnelSeed("exit-de-1", "master-xa-1", "salt"))
	spec := domain.NodeSpec{
		Role: domain.RoleMaster,
		WGServer: domain.WGServerSpec{
			ListenPort: 443, AddressPool: "10.80.0.0/24", MTU: 1360,
		},
		Firewall: domain.FirewallSpec{WGPort: 443},
		Master: &domain.MasterSpec{
			BindAddress:        "10.80.0.1",
			RedirPort:          7895,
			ExternalController: "10.20.25.254:9090",
			Balance:            "consistent-hashing",
			DirectCIDRs:        []string{"10.0.0.0/8", "192.168.0.0/16"},
			DirectGeo:          []string{"RU"},
			SnifferSkip:        []string{"+.themoviedb.org"},
			ExitTunnels: []domain.ExitTunnel{{
				Name: "exit-de-1", Endpoint: "198.51.100.7:51820",
				ServerPublicKey: "EXITPUB==", TunnelIP: "10.81.0.2", MTU: 1360, AWG: &awg,
			}},
			Custom: domain.CustomConfig{
				Files: []domain.ManagedFile{{Path: "direct-domains.yaml", Content: "payload:\n  - example.com\n"}},
			},
		},
	}
	return spec, kp.PrivateKey
}

func TestMihomoRedirPlannerRestartsWhenListenerDown(t *testing.T) {
	spec, _ := masterSpec(t) // BindAddress 10.80.0.1, RedirPort 7895
	pl := mihomoRedirPlanner{
		compose:   "/etc/mihomo/docker-compose.yml",
		listening: func(string) bool { return false }, // mihomo lost its redir bind
		localUp:   func(string) bool { return true },  // but wg0/10.80.0.1 is up
	}
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionUpdate {
		t.Fatalf("want one update (restart) action, got %+v", acts)
	}
	if !strings.Contains(acts[0].Display, "restart mihomo") {
		t.Fatalf("expected a restart command, got display %q", acts[0].Display)
	}
}

func TestMihomoRedirPlannerNoOpWhenListening(t *testing.T) {
	spec, _ := masterSpec(t)
	pl := mihomoRedirPlanner{
		listening: func(string) bool { return true },
		localUp:   func(string) bool { return true },
	}
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionNoChange {
		t.Fatalf("want no-change when the listener is up, got %+v", acts)
	}
}

// While the bind address is not yet up locally (wg0/wg-easy down or mid-recreate)
// the planner must defer — never probe, never restart — so it cannot thrash mihomo.
func TestMihomoRedirPlannerDefersWhenBindAddrDown(t *testing.T) {
	spec, _ := masterSpec(t)
	probed := false
	pl := mihomoRedirPlanner{
		listening: func(string) bool { probed = true; return false },
		localUp:   func(string) bool { return false },
	}
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionNoChange {
		t.Fatalf("want deferred no-change when bind addr not local, got %+v", acts)
	}
	if probed {
		t.Fatal("must not probe the listener before the bind address is up locally")
	}
}

func TestMasterPlanModeWritesNothing(t *testing.T) {
	paths := testPaths(t)
	spec, priv := masterSpec(t)

	eng := reconcile.NewEngine(nil, Planners(Input{Paths: paths, PrivateKey: priv})...)
	report, err := eng.Reconcile(context.Background(), spec, reconcile.ModePlan)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	for _, p := range []string{paths.MihomoConfig, paths.DirectNetworks, paths.NFT, paths.FirewallNFT} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("plan mode wrote %s; dry-run must not mutate", p)
		}
	}

	out := report.String()
	for _, want := range []string{
		"mihomo (data plane)", "type: wireguard", "amnezia-wg-option",
		"master NAT (nftables)", "dnat to 10.80.0.1:7895", "udp dport 443 drop",
		"master firewall (nftables)", `iifname "zt*" accept`,
		"direct-domains.yaml",
		"container stack (docker compose)", "wg-easy", "mihomo", "EXPERIMENTAL_AWG=true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output missing %q\n---\n%s", want, out)
		}
	}
	// Secret: master WG key must not appear.
	if strings.Contains(out, priv) {
		t.Error("plan output leaked the master private key")
	}
}

func TestMasterApplyWritesMihomoConfig(t *testing.T) {
	paths := testPaths(t)
	spec, priv := masterSpec(t)

	// Isolate the mihomo planner. Stub the reload so the apply does not dial the
	// (non-routable on a dev box) mgmt controller; the FileActions still run.
	noReload := func(context.Context, string, string, []byte) error { return nil }
	eng := reconcile.NewEngine(nil, mihomoPlanner{paths: paths, privateKey: priv, reload: noReload})
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)

	data, err := os.ReadFile(paths.MihomoConfig)
	if err != nil {
		t.Fatalf("mihomo config not written: %v", err)
	}
	if !strings.Contains(string(data), priv) {
		t.Error("applied mihomo config should contain the real master private key")
	}
	if _, err := os.Stat(paths.DirectNetworks); err != nil {
		t.Errorf("direct-networks.yaml not written: %v", err)
	}
}

// seedMihomoConfig writes the current rendered config to disk so a subsequent
// NON-proxy change exercises the hot-reload path (a proxy change forces a restart).
func seedMihomoConfig(t *testing.T, paths Paths, spec domain.NodeSpec, priv string) {
	t.Helper()
	cfg, err := mihomo.RenderConfig(mihomo.RenderInput{Spec: *spec.Master, PrivateKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.MihomoConfig, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestMihomoReloadPreferredOverRestart proves a NON-proxy config change (e.g. a
// sniffer/rule tweak or draining an exit) is hot-reloaded via the Clash API rather
// than restarting the container — so other clients keep their connections.
func TestMihomoReloadPreferredOverRestart(t *testing.T) {
	paths := testPaths(t)
	spec, priv := masterSpec(t)
	// A Clash API secret set via overrides must reach the reload call.
	spec.Master.Custom.Overrides = map[string]any{"secret": "topsecret"}
	seedMihomoConfig(t, paths, spec, priv)

	var reloadCalls int
	var gotSecret string
	reload := func(_ context.Context, addr, secret string, cfg []byte) error {
		reloadCalls++
		gotSecret = secret
		if addr == "" || len(cfg) == 0 {
			t.Errorf("reload got addr=%q cfgLen=%d", addr, len(cfg))
		}
		return nil
	}
	// A NON-proxy change (sniffer skip-domain) triggers an apply via hot reload.
	spec.Master.SnifferSkip = append(spec.Master.SnifferSkip, "+.example.com")

	pl := mihomoPlanner{paths: paths, privateKey: priv, reload: reload,
		restart: func(context.Context) error { t.Error("non-proxy change must NOT restart"); return nil }}
	if _, err := reconcile.NewEngine(nil, pl).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if reloadCalls != 1 {
		t.Errorf("expected exactly one hot reload, got %d", reloadCalls)
	}
	if gotSecret != "topsecret" {
		t.Errorf("clash secret not forwarded from overrides: %q", gotSecret)
	}

	// Config now matches disk ⇒ no further reload (and no restart).
	reloadCalls = 0
	acts, _ := pl.Plan(context.Background(), spec)
	for _, a := range acts {
		if a.Changes() && strings.Contains(a.Summary, "reload") {
			t.Errorf("unchanged config must not reload mihomo: %+v", a)
		}
	}
}

// TestMihomoRejectedConfigNotRestarted proves a config mihomo REJECTS (a non-
// transport error) surfaces as a reconcile error WITHOUT a fallback restart, so the
// previous good config keeps running instead of restarting into a bad one.
func TestMihomoRejectedConfigNotRestarted(t *testing.T) {
	paths := testPaths(t)
	spec, priv := masterSpec(t)
	seedMihomoConfig(t, paths, spec, priv)
	spec.Master.SnifferSkip = append(spec.Master.SnifferSkip, "+.example.com") // non-proxy change ⇒ hot-reload path

	rejected := errors.New("controller rejected config (HTTP 400)")
	reload := func(context.Context, string, string, []byte) error { return rejected }

	pl := mihomoPlanner{paths: paths, privateKey: priv, reload: reload,
		restart: func(context.Context) error { t.Error("rejected config must NOT restart"); return nil }}
	_, err := reconcile.NewEngine(nil, pl).Reconcile(context.Background(), spec, reconcile.ModeApply)
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected the rejection to surface as a reconcile error, got %v", err)
	}
}

// TestMihomoRestartsOnProxyChange proves a wireguard-proxy AmneziaWG-param change
// forces a full container restart (a Clash API hot reload can't re-init the proxy
// device, so new S/H params would silently never apply — the an earlier finding deploy gap).
func TestMihomoRestartsOnProxyChange(t *testing.T) {
	paths := testPaths(t)
	spec, priv := masterSpec(t)
	seedMihomoConfig(t, paths, spec, priv)

	// Change a wireguard-proxy AmneziaWG param.
	spec.Master.ExitTunnels[0].AWG.Shared.S4++

	var restarts, reloads int
	pl := mihomoPlanner{paths: paths, privateKey: priv,
		reload:  func(context.Context, string, string, []byte) error { reloads++; return nil },
		restart: func(context.Context) error { restarts++; return nil }}
	if _, err := reconcile.NewEngine(nil, pl).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if restarts != 1 {
		t.Errorf("proxy AWG change must restart mihomo once, got %d", restarts)
	}
	if reloads != 0 {
		t.Errorf("proxy change must NOT hot-reload (silent no-op), got %d reloads", reloads)
	}
}

func TestMasterExtraFilesWritten(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)

	eng := reconcile.NewEngine(nil, extraFilesPlanner{dir: paths.ExtraFilesDir})
	if _, err := eng.Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(paths.ExtraFilesDir, "direct-domains.yaml"))
	if err != nil {
		t.Fatalf("extra file not written: %v", err)
	}
	if !strings.Contains(string(got), "example.com") {
		t.Errorf("extra file content wrong: %q", got)
	}
}

// writeMasterCompose renders the master compose file exactly as composePlanner
// would and writes it to disk, so a follow-up Plan sees an unchanged file.
func writeMasterCompose(t *testing.T, path string, spec domain.NodeSpec) {
	t.Helper()
	yamlText, err := compose.RenderMasterCompose(compose.RenderInput{
		Compose:          spec.Master.Compose,
		ClientListenPort: spec.WGServer.ListenPort,
		ClientPool:       spec.WGServer.AddressPool,
		MgmtAddr:         masterMgmtAddr(spec),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(yamlText), 0o644); err != nil {
		t.Fatal(err)
	}
}

// lastKind returns the Kind of the final action a planner produced.
func lastKind(actions []reconcile.Action) reconcile.ActionKind {
	return actions[len(actions)-1].Kind
}

func TestComposePlannerIdempotentAndEnsureUp(t *testing.T) {
	spec, _ := masterSpec(t)

	t.Run("file changed ⇒ up -d", func(t *testing.T) {
		paths := testPaths(t) // compose file absent ⇒ create
		pl := composePlanner{path: paths.Compose, up: func(string) bool { return true }}
		actions, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if got := lastKind(actions); got != reconcile.ActionExec {
			t.Fatalf("changed compose: want exec (up -d), got %q in %+v", got, actions)
		}
	})

	t.Run("unchanged + up ⇒ no-change", func(t *testing.T) {
		paths := testPaths(t)
		writeMasterCompose(t, paths.Compose, spec)
		pl := composePlanner{path: paths.Compose, up: func(string) bool { return true }}
		actions, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if got := lastKind(actions); got != reconcile.ActionNoChange {
			t.Fatalf("steady state must not churn: want no-change, got %q in %+v", got, actions)
		}
		if r := (reconcile.Report{Plans: []reconcile.Plan{{Actions: actions}}}); r.ChangeCount() != 0 {
			t.Errorf("steady-state pass reports %d changes, want 0", r.ChangeCount())
		}
	})

	t.Run("unchanged + down ⇒ up -d", func(t *testing.T) {
		paths := testPaths(t)
		writeMasterCompose(t, paths.Compose, spec)
		pl := composePlanner{path: paths.Compose, up: func(string) bool { return false }}
		actions, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if got := lastKind(actions); got != reconcile.ActionExec {
			t.Fatalf("stack down must be brought up: want exec, got %q in %+v", got, actions)
		}
	})
}

func seedWGEasyDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE interfaces_table (
		name TEXT PRIMARY KEY,
		port INTEGER DEFAULT 51820, ipv4_cidr TEXT DEFAULT '10.8.0.0/24', mtu INTEGER DEFAULT 1420,
		j_c INTEGER DEFAULT 7, j_min INTEGER DEFAULT 10, j_max INTEGER DEFAULT 1000,
		s1 INTEGER DEFAULT 128, s2 INTEGER DEFAULT 56, s3 INTEGER, s4 INTEGER,
		h1 TEXT, h2 TEXT, h3 TEXT, h4 TEXT,
		i1 TEXT, i2 TEXT, i3 TEXT, i4 TEXT, i5 TEXT, private_key TEXT DEFAULT 'PRIV'
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO interfaces_table (name) VALUES ('wg0')`); err != nil {
		t.Fatal(err)
	}
}

func TestWGEasyPlannerPendingWhenDBMissing(t *testing.T) {
	paths := testPaths(t) // WGEasyDB points at a non-existent temp path
	spec, _ := masterSpec(t)
	// Master client-facing AWG (normally from keybroker); set one here.
	awg := wg.DeriveAWGParams(wg.TunnelSeed("master-xa-1", "clients", "salt"))
	spec.WGServer.AWG = &awg

	actions, err := wgEasyPlanner{dbPath: paths.WGEasyDB, iface: "wg0"}.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].Changes() {
		t.Fatalf("expected a single no-change (pending) action, got %+v", actions)
	}
	if !strings.Contains(actions[0].Summary, "pending") {
		t.Errorf("expected pending notice, got %q", actions[0].Summary)
	}
}

func TestWGEasyPlannerUpdatesSeededDB(t *testing.T) {
	paths := testPaths(t)
	seedWGEasyDB(t, paths.WGEasyDB)
	spec, _ := masterSpec(t)
	awg := wg.DeriveAWGParams(wg.TunnelSeed("master-xa-1", "clients", "salt"))
	spec.WGServer.AWG = &awg

	pl := wgEasyPlanner{dbPath: paths.WGEasyDB, iface: "wg0"}
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	// Defaults differ from desired ⇒ update + restart.
	if len(actions) != 2 || actions[0].Kind != reconcile.ActionUpdate {
		t.Fatalf("expected update+restart, got %+v", actions)
	}

	// Apply the DB update directly (the restart exec would fail on a dev box),
	// then re-plan ⇒ no change.
	if err := wgeasy.UpdateInterface(context.Background(), paths.WGEasyDB, "wg0",
		wgeasy.ColumnsFromSpec(spec.WGServer)); err != nil {
		t.Fatal(err)
	}
	actions2, _ := pl.Plan(context.Background(), spec)
	if len(actions2) != 1 || actions2[0].Changes() {
		t.Errorf("second plan should be no-change, got %+v", actions2)
	}
}

// TestWGEasyPlannerEnforcesPort proves a manifest port change is pushed into a
// persisted wg-easy DB (the bug: INIT_PORT is ignored once the DB exists).
func TestWGEasyPlannerEnforcesPort(t *testing.T) {
	paths := testPaths(t)
	seedWGEasyDB(t, paths.WGEasyDB) // seeds port=51820 (wg-easy default)
	spec, _ := masterSpec(t)        // desired ListenPort=443
	awg := wg.DeriveAWGParams(wg.TunnelSeed("master-xa-1", "clients", "salt"))
	spec.WGServer.AWG = &awg

	pl := wgEasyPlanner{dbPath: paths.WGEasyDB, iface: "wg0"}
	if _, err := pl.Plan(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if err := wgeasy.UpdateInterface(context.Background(), paths.WGEasyDB, "wg0",
		wgeasy.ColumnsFromSpec(spec.WGServer)); err != nil {
		t.Fatal(err)
	}
	got, _, err := wgeasy.ReadInterface(context.Background(), paths.WGEasyDB, "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != 443 {
		t.Errorf("configured client port not enforced in DB: port=%d (want 443)", got.Port)
	}
}

// TestMasterNATReloadGate covers the live-kernel reload gate: when the rendered
// ruleset is unchanged but the kernel no longer has the table (post-reboot), the
// planner must re-emit `nft -f`; when the kernel reflects it, it must not.
func TestMasterNATReloadGate(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)

	loaded := false
	pl := masterNATPlanner{path: paths.NFT, clientIface: "wg0",
		loaded: func() bool { return loaded }}

	// First apply writes the ruleset file (the nft exec fails on a dev box, but the
	// FileAction runs first, so the file lands).
	eng := reconcile.NewEngine(nil, pl)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	if _, err := os.Stat(paths.NFT); err != nil {
		t.Fatalf("NAT ruleset not written: %v", err)
	}

	// File unchanged + kernel table MISSING ⇒ reload.
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "reload master NAT") {
		t.Errorf("expected a reload action when the kernel table is missing, got %+v", acts)
	}

	// File unchanged + kernel table PRESENT ⇒ no change.
	loaded = true
	acts2, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts2 {
		if a.Changes() {
			t.Errorf("expected no-change when the kernel reflects the ruleset, got %+v", acts2)
		}
	}
}

// TestMasterFirewallReloadGate covers the master input-firewall planner's
// live-kernel reload gate (the gap this work closed: the master had no reconciled
// input firewall, so a reboot left it with none until re-provisioned).
func TestMasterFirewallReloadGate(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)

	loaded := false
	pl := firewallPlanner{path: paths.FirewallNFT, loaded: func() bool { return loaded }}

	// First apply writes the ruleset file (the nft exec fails on a dev box, but the
	// FileAction runs first, so the file lands).
	eng := reconcile.NewEngine(nil, pl)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	data, err := os.ReadFile(paths.FirewallNFT)
	if err != nil {
		t.Fatalf("firewall ruleset not written: %v", err)
	}
	for _, want := range []string{"table inet wgfleet", "policy drop;", `iifname "zt*" accept`, "udp dport 443 accept"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("master firewall ruleset missing %q:\n%s", want, data)
		}
	}

	// File unchanged + kernel table MISSING ⇒ reload (post-reboot self-heal).
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "reload master firewall") {
		t.Errorf("expected a reload action when the kernel table is missing, got %+v", acts)
	}

	// File unchanged + kernel table PRESENT ⇒ no change.
	loaded = true
	acts2, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts2 {
		if a.Changes() {
			t.Errorf("expected no-change when the kernel reflects the ruleset, got %+v", acts2)
		}
	}
}

func TestMasterForwardPlanner(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{}}

	// Forwarding off, DOCKER-USER present, rules absent ⇒ enable + insert both.
	t.Run("applies when missing", func(t *testing.T) {
		pl := masterForwardPlanner{
			clientIface: "wg0",
			forwardOn:   func() bool { return false },
			chainExists: func() bool { return true },
			rulePresent: func([]string) bool { return false },
		}
		acts, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		if !hasChangingSummary(acts, "enable IPv4 forwarding") {
			t.Errorf("expected ip_forward enable, got %+v", acts)
		}
		if !hasChangingSummary(acts, "client→uplink") || !hasChangingSummary(acts, "return traffic") {
			t.Errorf("expected both DOCKER-USER inserts, got %+v", acts)
		}
	})

	// Everything already in place ⇒ no change (idempotent, no perpetual drift).
	t.Run("no change when present", func(t *testing.T) {
		pl := masterForwardPlanner{
			clientIface: "wg0",
			forwardOn:   func() bool { return true },
			chainExists: func() bool { return true },
			rulePresent: func([]string) bool { return true },
		}
		acts, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range acts {
			if a.Changes() {
				t.Errorf("expected no-change when forwarding already set, got %+v", acts)
			}
		}
	})

	// DOCKER-USER absent (docker not up yet) ⇒ defer the inserts, never fail.
	t.Run("defers when docker not up", func(t *testing.T) {
		pl := masterForwardPlanner{
			clientIface: "wg0",
			forwardOn:   func() bool { return true },
			chainExists: func() bool { return false },
			rulePresent: func([]string) bool { return false },
		}
		acts, err := pl.Plan(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range acts {
			if a.Changes() {
				t.Errorf("expected no insert while DOCKER-USER is absent, got %+v", acts)
			}
		}
	})
}

func hasChangingSummary(acts []reconcile.Action, substr string) bool {
	for _, a := range acts {
		if a.Changes() && strings.Contains(a.Summary, substr) {
			return true
		}
	}
	return false
}
