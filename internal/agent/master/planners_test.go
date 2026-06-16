package master

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/domain"
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

func TestMasterPlanModeWritesNothing(t *testing.T) {
	paths := testPaths(t)
	spec, priv := masterSpec(t)

	eng := reconcile.NewEngine(nil, Planners(Input{Paths: paths, PrivateKey: priv})...)
	report, err := eng.Reconcile(context.Background(), spec, reconcile.ModePlan)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	for _, p := range []string{paths.MihomoConfig, paths.DirectNetworks, paths.NFT} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("plan mode wrote %s; dry-run must not mutate", p)
		}
	}

	out := report.String()
	for _, want := range []string{
		"mihomo (data plane)", "type: wireguard", "amnezia-wg-option",
		"master NAT (nftables)", "dnat to 10.80.0.1:7895", "udp dport 443 drop",
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

	// Isolate the mihomo planner so its FileActions run before the (failing on a
	// dev box) systemctl exec.
	eng := reconcile.NewEngine(nil, mihomoPlanner{paths: paths, privateKey: priv})
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
