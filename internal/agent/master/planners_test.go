package master

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/netfw"
	"github.com/shidoh/wgfleet/internal/wg"
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
		compose:      "/etc/mihomo/docker-compose.yml",
		listening:    func(string) bool { return false }, // mihomo lost its redir bind
		udpListening: func(string) bool { return true },  // TPROXY is fine; only TCP is down
		localUp:      func(string) bool { return true },  // and wg0/10.80.0.1 is up
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
		// Both probes must be stubbed. Leaving this nil fell through to the real
		// socketListening, which shells out to `ss`: absent on a macOS laptop (the
		// call errors and fails OPEN, so the test passed) and present on the Linux CI
		// runner (it reports nothing bound on 10.80.0.1:7896, so the planner asked for
		// a restart and the test failed). A unit test must not depend on the host's
		// socket table, or on which tools the host happens to ship.
		udpListening: func(string) bool { return true },
		localUp:      func(string) bool { return true },
	}
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(acts) != 1 || acts[0].Kind != reconcile.ActionNoChange {
		t.Fatalf("want no-change when the listener is up, got %+v", acts)
	}
}

// While the bind address is not yet up locally (wg0 down or mid-recreate)
// the planner must defer — never probe, never restart — so it cannot thrash mihomo.
func TestMihomoRedirPlannerDefersWhenBindAddrDown(t *testing.T) {
	spec, _ := masterSpec(t)
	probed := false
	pl := mihomoRedirPlanner{
		listening:    func(string) bool { probed = true; return false },
		udpListening: func(string) bool { probed = true; return false },
		localUp:      func(string) bool { return false },
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
		// The QUIC drop is GONE once UDP can be proxied: it lived at the dstnat hook
		// and shadowed the interception at mangle, so keeping both black-holed every
		// client's HTTP/3. The interception itself is what must be here now.
		"master NAT (nftables)", "dnat to 10.80.0.1:7895", "tproxy ip to 10.80.0.1:7896",
		"master firewall (nftables)", `iifname "zt*" accept`,
		"direct-domains.yaml",
		"container stack (docker compose)", "mihomo",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan output missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "wg-easy") {
		t.Errorf("plan still mentions wg-easy\n---\n%s", out)
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

// TestMihomoRejectedConfigRolledBackOnDisk proves that when mihomo rejects a config
// the FILE is restored to the previous good one, not just the in-memory config left
// alone. Leaving the rejected bytes on disk is a delayed-action failure: mihomo keeps
// running the old config, so the pass looks merely errored — but the next restart for
// any unrelated reason (host reboot, compose planner, mihomoRedirPlanner's rebind
// self-heal, mihomoWGDupPlanner) loads the bad file and takes the data plane down,
// far from the change that caused it.
func TestMihomoRejectedConfigRolledBackOnDisk(t *testing.T) {
	paths := testPaths(t)
	spec, priv := masterSpec(t)
	seedMihomoConfig(t, paths, spec, priv)
	good, err := os.ReadFile(paths.MihomoConfig)
	if err != nil {
		t.Fatal(err)
	}
	spec.Master.SnifferSkip = append(spec.Master.SnifferSkip, "+.example.com") // non-proxy change ⇒ hot-reload path

	reload := func(context.Context, string, string, []byte) error {
		return errors.New("controller rejected config (HTTP 400)")
	}
	pl := mihomoPlanner{paths: paths, privateKey: priv, reload: reload,
		restart: func(context.Context) error { t.Error("rejected config must NOT restart"); return nil }}
	if _, err := reconcile.NewEngine(nil, pl).Reconcile(context.Background(), spec, reconcile.ModeApply); err == nil {
		t.Fatal("expected the rejection to surface as a reconcile error")
	}

	onDisk, err := os.ReadFile(paths.MihomoConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, good) {
		t.Error("rejected config left on disk: a later restart would load it and drop the data plane")
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
	yamlText, err := compose.RenderMasterCompose(masterComposeInput(spec, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// 0600, matching what composePlanner renders. Seeding 0644 here made every
	// "steady state" assertion see a legitimate mode-drift repair and fail.
	if err := os.WriteFile(path, []byte(yamlText), 0o600); err != nil {
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

// TestMasterNATReloadGate covers the live-kernel reload gate: when the rendered
// ruleset is unchanged but the kernel no longer has the table (post-reboot), the
// planner must re-emit `nft -f`; when the kernel reflects it, it must not.
func TestMasterNATReloadGate(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)

	loaded := false
	// The tproxy policy routing has its own gate and its own test; stub it as
	// present so this one keeps measuring only the nft reload gate.
	pl := masterNATPlanner{path: paths.NFT, clientIface: "wg0",
		loaded: func() bool { return loaded }, tproxyReady: func() bool { return true }}

	// First apply writes the ruleset file (the nft exec fails on a dev box, but the
	// FileAction runs first, so the file lands).
	eng := reconcile.NewEngine(nil, pl)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	if _, err := os.Stat(paths.NFT); err != nil {
		t.Fatalf("NAT ruleset not written: %v", err)
	}

	// The apply-marker stands in for the exec having succeeded: `nft` does not exist
	// on a dev box, so without this the planner correctly keeps RETRYING the apply and
	// this test cannot reach the question it is asking.
	markNFTApplied(t, paths.NFT)

	// Applied + kernel table MISSING ⇒ reload.
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "kernel table missing") {
		t.Errorf("expected a reload action when the kernel table is missing, got %+v", acts)
	}

	// Applied + kernel table PRESENT ⇒ no change.
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

	// The exec failed on this dev box, so no applied-marker exists and the next pass
	// must RETRY rather than call the ruleset done.
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "apply master firewall atomically") {
		t.Errorf("a failed apply was recorded as finished, got %+v", acts)
	}
	writeAppliedMarker(t, paths.FirewallNFT)

	// Ruleset applied + kernel table MISSING ⇒ reload (post-reboot self-heal).
	acts, err = pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "kernel table missing") {
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

// (TestMasterForwardPlanner moved to internal/agent/dockerfw, where the shared
// ForwardPlanner now lives.)

func hasChangingSummary(acts []reconcile.Action, substr string) bool {
	for _, a := range acts {
		if a.Changes() && strings.Contains(a.Summary, substr) {
			return true
		}
	}
	return false
}

// A compose file left group/world-readable by an older binary must be surfaced as
// a change. The chmod itself is
// covered by reconcile's own tests; what matters here is that the PLANNER does not
// treat a mode-only repair as steady state and skip it.
//
// Note the second action: composePlanner gates on Action.Changes(), which cannot
// distinguish "content changed" from "mode repaired", so a pure permission fix also
// re-runs `docker compose up -d`. Harmless (compose diffs the rendered service
// config, not file modes) but pinned here so the coupling is visible.
func TestComposePlannerSurfacesWorldReadableModeRepair(t *testing.T) {
	spec, _ := masterSpec(t)
	paths := testPaths(t)
	writeMasterCompose(t, paths.Compose, spec)
	if err := os.Chmod(paths.Compose, 0o644); err != nil {
		t.Fatal(err)
	}

	pl := composePlanner{path: paths.Compose, up: func(string) bool { return true }}
	actions, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) == 0 || !actions[0].Changes() {
		t.Fatalf("a world-readable compose file must not read as steady state, got %+v", actions)
	}
	if !strings.Contains(actions[0].Summary, "repairing mode to 600") {
		t.Fatalf("expected a mode-repair action, got %q", actions[0].Summary)
	}
}

// TPROXY is not just an nft rule: a marked packet still has to be told to stay on
// this host. Without `ip rule fwmark <m> lookup <t>` and a `local default` route in
// that table, the kernel routes the intercepted datagram normally and the
// transparent socket never sees it — client UDP would be dropped instead of
// leaked, which trades one broken behaviour for another.
func TestMasterNATInstallsTProxyPolicyRouting(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)

	pl := masterNATPlanner{path: paths.NFT, clientIface: "wg0",
		loaded: func() bool { return false }, tproxyReady: func() bool { return false }}

	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Summary + " | " + a.Display + "\n"
	}
	for _, want := range []string{
		fmt.Sprintf("fwmark %#x", netfw.TProxyMark),
		fmt.Sprintf("table %d", netfw.TProxyTable),
		"local",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("the plan never installs %q; TPROXY'd UDP has no route home:\n%s", want, dump)
		}
	}
}

// And the same drift repair the nft table gets: someone flushing `ip rule` must
// not leave the master silently dropping every client datagram until a reboot.
func TestMasterNATRepairsTProxyPolicyRoutingDrift(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)

	ready := false
	pl := masterNATPlanner{path: paths.NFT, clientIface: "wg0",
		loaded: func() bool { return true }, tproxyReady: func() bool { return ready }}

	eng := reconcile.NewEngine(nil, pl)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	// `nft` does not exist on a dev box, so the apply legitimately fails and leaves no
	// applied-marker. Stand in for a successful one, or the NAT half never goes quiet
	// and this test cannot measure the tproxy half on its own.
	markNFTApplied(t, paths.NFT)

	// nft unchanged and loaded, but the policy routing is gone ⇒ reinstall it.
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "tproxy") {
		t.Errorf("no repair when the tproxy policy routing is missing: %+v", acts)
	}

	// Everything in place ⇒ nothing to do.
	ready = true
	acts2, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts2 {
		if a.Changes() {
			t.Errorf("steady state must not re-run the tproxy setup: %+v", acts2)
		}
	}
}

// The IPv6 refusal must be applied by the same planner, in the same pass, as the
// rest of the client policy. Split across planners the two halves converge at
// different times, and for those seconds a client holds a ::/0 route into a master
// that ignores it — which is the black hole, not the block.
func TestMasterNATAppliesTheIPv6Refusal(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)
	prefix, err := wg.ClientULAFor(spec.WGServer.AddressPool)
	if err != nil {
		t.Fatal(err)
	}
	spec.Master.ClientWG = &domain.ClientWGSpec{
		ListenPort: 443, AddressPool: spec.WGServer.AddressPool,
		ServerAddress: "10.80.0.1", IPv6Prefix: prefix.String(),
	}

	pl := masterNATPlanner{path: paths.NFT, v6Path: paths.V6NFT, clientIface: "wg0",
		loaded: func() bool { return true }, tproxyReady: func() bool { return true }}
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Summary + " | " + a.Display + "\n"
	}
	if !strings.Contains(dump, "reject with icmpv6 type admin-prohibited") {
		t.Errorf("no audible IPv6 refusal in the plan:\n%s", dump)
	}
	// Without forwarding the packet never reaches a forward chain and no ICMP is
	// generated at all — the reject rule would be decoration.
	if !strings.Contains(dump, "net.ipv6.conf.all.forwarding=1") {
		t.Errorf("IPv6 forwarding is never enabled, so the refusal is unreachable:\n%s", dump)
	}
}

// With no prefix the master must not touch IPv6 at all — not the ruleset, and
// certainly not the forwarding sysctl.
func TestMasterNATLeavesIPv6AloneByDefault(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)

	pl := masterNATPlanner{path: paths.NFT, v6Path: paths.V6NFT, clientIface: "wg0",
		loaded: func() bool { return true }, tproxyReady: func() bool { return true }}
	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if strings.Contains(a.Summary+a.Display, "ipv6") || strings.Contains(a.Summary+a.Display, "icmpv6") {
			t.Errorf("IPv6 touched with the block off: %s | %s", a.Summary, a.Display)
		}
	}
}

// markNFTApplied records the ruleset currently on disk as successfully applied,
// which is what reconcile.NFTApply's OnApplied hook does on a real node.
func markNFTApplied(t *testing.T, rulesetPath string) {
	t.Helper()
	b, err := os.ReadFile(rulesetPath)
	if err != nil {
		t.Fatalf("read ruleset: %v", err)
	}
	sum := sha256.Sum256(b)
	if err := os.WriteFile(reconcile.NFTAppliedMarker(rulesetPath),
		[]byte(hex.EncodeToString(sum[:])), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
}

// writeAppliedMarker records the digest NFTApply would have recorded had the exec
// succeeded, so a test on a box with no nft can reach the states beyond the retry.
func writeAppliedMarker(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if err := os.WriteFile(reconcile.NFTAppliedMarker(path),
		[]byte(hex.EncodeToString(sum[:])), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The nft table was watched and the sysctl that makes it reachable was not, so a
// `sysctl --system`, a hardening drop-in or a package postinst could return
// net.ipv6.conf.all.forwarding to 0 with the ruleset on disk and the table in the
// kernel both untouched — and the reconciler, gating on "did the nft actions
// change", had nothing to do, forever. The kernel then discards client IPv6 before
// any chain runs, no ICMPv6 is generated, and every client holding ::/0 is back in
// the silent black hole the feature exists to replace.
func TestMasterNATRepairsIPv6ForwardingWithoutTheRulesetChanging(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)
	prefix, perr := wg.ClientULAFor(spec.WGServer.AddressPool)
	if perr != nil {
		t.Fatal(perr)
	}
	spec.Master.ClientWG = &domain.ClientWGSpec{
		ListenPort: 443, AddressPool: spec.WGServer.AddressPool,
		ServerAddress: "10.80.0.1", IPv6Prefix: prefix.String(),
	}

	forwarding := false
	pl := masterNATPlanner{
		path: paths.NFT, v6Path: paths.V6NFT, clientIface: "wg0",
		loaded:       func() bool { return true },
		v6Loaded:     func() bool { return true },
		v6Forwarding: func() bool { return forwarding },
		tproxyReady:  func() bool { return true },
	}
	// Write both rulesets and record them as applied, so nothing about the nft half
	// is changing on the pass under test. Plan() renders; the FileActions only touch
	// disk in apply mode, and the exec beside them would fail on a box with no nft.
	first, ferr := pl.Plan(context.Background(), spec)
	if ferr != nil {
		t.Fatal(ferr)
	}
	applyNonExec(t, first)
	writeAppliedMarker(t, paths.NFT)
	writeAppliedMarker(t, paths.V6NFT)

	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "enable IPv6 forwarding") {
		t.Errorf("forwarding is off and the ruleset is unchanged, so nothing repairs it:\n%s", dumpActions(acts))
	}

	// And once the kernel agrees, the pass is quiet again.
	forwarding = true
	acts, err = pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if hasChangingSummary(acts, "enable IPv6 forwarding") {
		t.Errorf("forwarding is already on and the planner still wants to set it:\n%s", dumpActions(acts))
	}
}

// dumpActions renders a plan for a failure message.
func dumpActions(acts []reconcile.Action) string {
	var b strings.Builder
	for _, a := range acts {
		b.WriteString(a.Summary + " | " + a.Display + "\n")
	}
	return b.String()
}

// applyNonExec runs a plan's file writes without its commands, so a test on a box
// with no nft can reach the states that only exist after the ruleset is on disk.
// The engine is the only thing that can apply an action, and it would run the execs
// too, so the ruleset is written directly from what the plan says it should hold.
func applyNonExec(t *testing.T, acts []reconcile.Action) {
	t.Helper()
	for _, a := range acts {
		if a.Kind != reconcile.ActionCreate && a.Kind != reconcile.ActionUpdate {
			continue
		}
		if !a.Changes() {
			continue
		}
		if err := os.WriteFile(a.Target, []byte(a.Display), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// iproute2 assigns an unnumbered rule `lowest existing - 1`, so the same rule
// lands in different places depending on what else is in the table when it is
// added. Observed on the stand 2026-09-05: with the namespace exemptions present
// this rule sat at 389, and without them at 32765.
func TestTProxyRuleCarriesAnExplicitPriority(t *testing.T) {
	var dump string
	for _, a := range tproxyRouteActions() {
		dump += a.Display + "\n"
	}
	want := "ip rule add fwmark 0x2 lookup 51821 pref 380"
	if !strings.Contains(dump, want) {
		t.Errorf("missing %q — the rule's position depends on what else is in the table:\n%s", want, dump)
	}
	// And it must sort ahead of the namespace exemptions: a packet the host has
	// already intercepted belongs on this host, whatever its destination.
	if netfw.TProxyRulePref >= netnsDirectRulePref {
		t.Errorf("the tproxy rule (%d) no longer precedes the namespace exemptions (%d)",
			netfw.TProxyRulePref, netnsDirectRulePref)
	}
}

// The destinations that bypass the interception are expressed twice — as an
// `ip rule` that routes them around the namespace, and as `ip daddr !=` exemptions
// in the ruleset that would otherwise read them as a leak. They must come from one
// place: a destination in one list and not the other is a dropped split tunnel if
// it drifted one way, and an open leak if it drifted the other.
func TestTheRoutingAndTheFirewallExemptTheSameDestinations(t *testing.T) {
	spec := netnsSpec()
	spec.Master.DirectCIDRs = []string{"10.0.0.0/8", "198.51.100.220/32"}

	routed := directDestinations(spec)
	guarded := NATInput(spec, "wg0", true).PrivateCIDRs

	if len(routed) != len(guarded) {
		t.Fatalf("the two lists have different lengths:\nrouted  %v\nguarded %v", routed, guarded)
	}
	for i := range routed {
		if routed[i] != guarded[i] {
			t.Errorf("entry %d differs: routed %q, guarded %q", i, routed[i], guarded[i])
		}
	}
	// And the client pool is in both: it is a destination clients reach over their
	// own interface, not something to intercept or to call a leak.
	var hasPool bool
	for _, c := range guarded {
		if c == spec.WGServer.AddressPool {
			hasPool = true
		}
	}
	if !hasPool {
		t.Errorf("the client pool is not among the exempt destinations: %v", guarded)
	}
}

// Once the interception lives in the namespace, the host's TPROXY policy routing
// is not merely unused — it is a second configuration armed alongside the first.
//
// Its rule sits at a LOWER priority than both the direct-destination exemptions and
// the rule that routes clients into the namespace, so anything that ever carried
// the mark again would be taken locally, past the whole scheme. On the live master
// the rule and its table outlived the move with nothing referencing them.
func TestTheHostTProxyRoutingIsWithdrawnOnceTheInterceptionMoves(t *testing.T) {
	live := func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case line == "ip rule list":
			return "380:\tfrom all fwmark 0x2 lookup 51821\n400:\tfrom all iif wg0 lookup 51822\n", nil
		case strings.Contains(line, "route show table 51821"):
			return "local default dev lo scope host\n", nil
		}
		return "", errors.New("absent")
	}
	acts := tproxyRouteTeardown(live)
	dump := displays(acts)
	for _, want := range []string{"ip rule del fwmark 0x2 lookup 51821", "ip route flush table 51821"} {
		if !strings.Contains(dump, want) {
			t.Errorf("the host keeps a second interception armed; missing %q:\n%s", want, dump)
		}
	}
}

// And a master that has already shed them says so instead of deleting nothing
// twice a minute.
func TestAWithdrawnTProxyRoutingIsNotWithdrawnAgain(t *testing.T) {
	empty := func(name string, args ...string) (string, error) {
		if name+" "+strings.Join(args, " ") == "ip rule list" {
			return "400:\tfrom all iif wg0 lookup 51822\n", nil
		}
		return "", nil
	}
	for _, a := range tproxyRouteTeardown(empty) {
		if a.Changes() {
			t.Errorf("a master with no tproxy routing left tried to remove it anyway: %s", a.Display)
		}
	}
}

// The dependency is only worth anything if the planner that needs it declares it.
//
// The mechanism was built, tested at the engine level and left unwired: the
// interface existed, the engine honoured it, and the one pair it was written for
// never used it — so the failure it describes was still available in production
// while a passing test suite said otherwise.
func TestTheMasterNATDeclaresItsDependencyOnlyWhileTheInterceptionHasMoved(t *testing.T) {
	moved := masterNATPlanner{netnsAttached: func() bool { return true }}
	if got := moved.DependsOn(); got != NetnsComponent {
		t.Errorf("a moved master's NAT does not wait for the namespace: DependsOn() = %q", got)
	}
	onHost := masterNATPlanner{netnsAttached: func() bool { return false }}
	if got := onHost.DependsOn(); got != "" {
		t.Errorf("a master that never moved waits for a namespace it does not use: DependsOn() = %q", got)
	}
	undecided := masterNATPlanner{}
	if got := undecided.DependsOn(); got != "" {
		t.Errorf("an undecided master must not depend on anything: DependsOn() = %q", got)
	}
}

// And the name has to match the component that actually runs, or the dependency is
// inert: the engine looks it up by string.
func TestTheDependencyNamesAComponentThisAgentRuns(t *testing.T) {
	ns := netnsPlanner{}
	if ns.Component() != NetnsComponent {
		t.Fatalf("the namespace planner calls itself %q while others depend on %q",
			ns.Component(), NetnsComponent)
	}
}

// The floor on the veth MTU, including the case it must NOT touch: an unreadable
// uplink stays zero, which means "leave the kernel's default alone".
func TestTheVethMTUIsFlooredButAnUnreadableUplinkIsNotInvented(t *testing.T) {
	for in, want := range map[int]int{
		0:    0,    // could not read
		-1:   0,    // nor this
		1360: 1500, // the client tunnel's MTU, which strangled mihomo's own
		1420: 1500, // a master whose default route is a tunnel
		1500: 1500,
		9000: 9000, // jumbo: the reason the uplink is read at all
	} {
		if got := mtuWithFloor(in); got != want {
			t.Errorf("mtuWithFloor(%d) = %d, want %d", in, got, want)
		}
	}
}

// A probe that could not run is not a probe reporting "already gone" — and here a
// wrong "gone" leaves a second interception armed beside the first.
func TestTProxyTeardownActsWhenTheKernelWillNotAnswer(t *testing.T) {
	silent := func(string, ...string) (string, error) { return "", errors.New("netlink is busy") }
	var changing int
	for _, a := range tproxyRouteTeardown(silent) {
		if a.Changes() {
			changing++
		}
	}
	if changing == 0 {
		t.Error("an unanswered probe was read as 'already withdrawn', leaving the host rules in place")
	}
}

// Re-provisioning a node that is already running loads the bootstrap baseline
// table again, next to the agent's own. The agent's ruleset is unchanged and
// present, so nothing re-applied it, and the baseline — policy drop, SSH and the
// overlay only — stayed for good: on the stand 2026-10-09 a re-provisioned master
// stopped answering its clients on UDP/443 while every check of its own table
// read clean. The baseline in the kernel is drift; applying the ruleset deletes it.
func TestMasterFirewallReappliesOverAReturnedBaseline(t *testing.T) {
	paths := testPaths(t)
	spec, _ := masterSpec(t)
	baseline := true
	pl := firewallPlanner{path: paths.FirewallNFT, loaded: func() bool { return true }, baseline: func() bool { return baseline }}
	eng := reconcile.NewEngine(nil, pl)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	writeAppliedMarker(t, paths.FirewallNFT)

	acts, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasChangingSummary(acts, "apply master firewall atomically") {
		t.Errorf("the ruleset was not re-applied over a returned baseline, got %+v", acts)
	}

	baseline = false
	acts, err = pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("re-applied with no baseline in the kernel: %+v", a)
		}
	}
}
