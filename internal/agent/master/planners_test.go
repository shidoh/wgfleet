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
			ListenPort: 443, AddressPool: "10.80.0.0/24",
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

func seedWGEasyDB(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE interfaces_table (
		name TEXT PRIMARY KEY,
		j_c INTEGER DEFAULT 7, j_min INTEGER DEFAULT 10, j_max INTEGER DEFAULT 1000,
		s1 INTEGER DEFAULT 128, s2 INTEGER DEFAULT 56, s3 INTEGER, s4 INTEGER,
		h1 TEXT, h2 TEXT, h3 TEXT, h4 TEXT, i1 TEXT, private_key TEXT DEFAULT 'PRIV'
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
	if err := wgeasy.UpdateAWG(context.Background(), paths.WGEasyDB, "wg0",
		wgeasy.ColumnsFromParams(*spec.WGServer.AWG)); err != nil {
		t.Fatal(err)
	}
	actions2, _ := pl.Plan(context.Background(), spec)
	if len(actions2) != 1 || actions2[0].Changes() {
		t.Errorf("second plan should be no-change, got %+v", actions2)
	}
}
