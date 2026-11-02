package master

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

func synthPlannerSpec() domain.NodeSpec {
	return domain.NodeSpec{
		Role: domain.RoleMaster,
		Master: &domain.MasterSpec{
			BindAddress: "10.80.0.1",
			ClientWG: &domain.ClientWGSpec{
				ListenPort: 443, AddressPool: "10.80.0.0/24", ServerAddress: "10.80.0.1", MTU: 1360,
			},
		},
	}
}

// The prober's interface must be created in the HOST namespace and moved, in that
// order. Verified on the stand: a WireGuard device keeps its UDP socket
// in the namespace where it was created, so creating it inside the namespace would
// leave it unable to reach the master's own client port at all — and the prober
// would report the path broken while the path was fine.
func TestProberIsCreatedInTheHostNamespaceThenMoved(t *testing.T) {
	run := func(context.Context, string, ...string) (string, error) {
		return "", errors.New("absent")
	}
	p := synthPlanner{
		confPath: t.TempDir() + "/synth.conf", run: run, serverPub: "SRV",
		synthKey: wg.KeyPair{PrivateKey: "priv", PublicKey: "PUB"},
	}
	acts, err := p.Plan(context.Background(), synthPlannerSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var order []string
	for _, a := range acts {
		order = append(order, a.Display)
	}
	joined := strings.Join(order, "\n")

	create := strings.Index(joined, "ip link add wgs0 type amneziawg")
	setconf := strings.Index(joined, "awg setconf wgs0")
	move := strings.Index(joined, "ip link set wgs0 netns wgfleet-synth")
	if create < 0 || setconf < 0 || move < 0 {
		t.Fatalf("the prober is not built:\n%s", joined)
	}
	if !(create < setconf && setconf < move) {
		t.Errorf("wrong order — the device must be created and configured before it moves:\n%s", joined)
	}
	// The endpoint has to be loopback: that keeps the encrypted leg off every real
	// interface, so this traffic cannot leave the box by any path but the tunnel.
	if !strings.Contains(joined, "netns add wgfleet-synth") {
		t.Errorf("the namespace is never created:\n%s", joined)
	}
}

// Converged: nothing to do. This runs every pass, and rebuilding the prober once
// a minute would make it a source of churn rather than a measurement.
func TestProberIsQuietOnceUp(t *testing.T) {
	dir := t.TempDir()
	p := synthPlanner{
		confPath: dir + "/synth.conf", resolvPath: dir + "/resolv.conf", serverPub: "SRV",
		synthKey: wg.KeyPair{PrivateKey: "priv", PublicKey: "PUB"},
		run: func(_ context.Context, _ string, args ...string) (string, error) {
			if strings.Contains(strings.Join(args, " "), "netns list") {
				return "wgfleet-synth\n", nil
			}
			return "wgs0: <POINTOPOINT,UP>\n", nil // the interface is there
		},
	}
	// First pass through the ENGINE, not applyNonExec: the prober's config is
	// rendered with a redactor, so its Display is the redacted text and writing that
	// back would leave a file that never matches the render — a prober "changed" on
	// every pass. The exec steps fail on a dev box and that is fine; the file lands
	// first, which is what the second pass reads.
	eng := reconcile.NewEngine(nil, p)
	_, _ = eng.Reconcile(context.Background(), synthPlannerSpec(), reconcile.ModeApply)

	acts, err := p.Plan(context.Background(), synthPlannerSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("a converged prober would still run %q", a.Display)
		}
	}
}

// No key, no prober — and no failure either. A master that cannot mint the key
// must still serve clients; it simply goes unmeasured.
func TestProberIsAbsentWithoutAKey(t *testing.T) {
	p := synthPlanner{confPath: t.TempDir() + "/synth.conf", resolvPath: t.TempDir() + "/resolv.conf", serverPub: "SRV"}
	acts, err := p.Plan(context.Background(), synthPlannerSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("a prober without a key would still run %q", a.Display)
		}
	}
}

// A pool with no room must not silently take a client's address.
func TestProberStandsDownOnATinyPool(t *testing.T) {
	spec := synthPlannerSpec()
	spec.Master.ClientWG.AddressPool = "10.80.0.0/30"
	p := synthPlanner{
		confPath: t.TempDir() + "/synth.conf", resolvPath: t.TempDir() + "/resolv.conf", serverPub: "SRV",
		synthKey: wg.KeyPair{PrivateKey: "priv", PublicKey: "PUB"},
	}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("a prober was built into a pool with no room: %q", a.Display)
		}
	}
}

// `awg setconf` applies what the file says and cannot express what it no longer
// says: a parameter the device already carries and the config has dropped stays
// on the device. Measured on the stand — the prober was built while
// the spec carried AmneziaWG 3.x parameters, the spec went back to 2.0, setconf
// re-applied cleanly, and the device kept its header protection key. The server
// had none, so not one handshake completed and every client-path probe was red,
// with the config on disk looking exactly right.
//
// This device is the judge of the automatic revert, so a prober that cannot
// handshake makes every migration look broken and reverts it.
func TestProberIsRebuiltWhenItsParametersChange(t *testing.T) {
	dir := t.TempDir()
	p := synthPlanner{
		confPath:  dir + "/synth.conf",
		serverPub: "SRV",
		synthKey:  wg.KeyPair{PrivateKey: "priv", PublicKey: "PUB"},
		run: func(_ context.Context, name string, args ...string) (string, error) {
			line := name + " " + strings.Join(args, " ")
			if strings.Contains(line, "netns list") {
				return synthNetns + "\n", nil
			}
			if strings.Contains(line, "link show "+synthIface) {
				return synthIface + " UP\n", nil // the device is already there
			}
			return "", nil
		},
	}
	// Seed a config that differs from what the next pass renders.
	if err := os.WriteFile(p.confPath, []byte("[Interface]\nPrivateKey = stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	acts, err := p.Plan(context.Background(), synthPlannerSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Display + "\n"
	}
	if !strings.Contains(dump, "ip link del "+synthIface) {
		t.Errorf("a parameter change was applied in place, so a dropped parameter would survive:\n%s", dump)
	}
	if !strings.Contains(dump, "ip link add "+synthIface) {
		t.Errorf("the prober was removed and never rebuilt:\n%s", dump)
	}
}

// The prober's device is created on the host and moved into its namespace, so a
// build interrupted between those two steps leaves it on the host — where the
// only check looks inside the namespace and cannot see it. Every pass afterwards
// plans the same `ip link add` and gets `File exists`.
//
// That is not a cosmetic loop: this device is the judge of the automatic revert,
// so a prober that cannot be built makes every migration look broken. Found on the
// stand after it had reverted a working migration three times and then
// given up on it.
func TestABuildLeftHalfwayIsClearedBeforeTheNextAttempt(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "netns list"):
			return synthNetns + "\n", nil
		// The namespace has no device: this is exactly the state a half-built prober
		// leaves behind, and the state that used to wedge the node.
		case strings.Contains(line, "netns exec "+synthNetns+" ip link show"):
			return "", errors.New("Device \"wgs0\" does not exist")
		}
		return "", errors.New("absent: " + line)
	}
	p := synthPlanner{
		run: run, confPath: t.TempDir() + "/wgs0.conf", serverPub: "SRV",
		synthKey: wg.KeyPair{PrivateKey: "priv", PublicKey: "PUB"},
	}
	acts, err := p.Plan(context.Background(), synthPlannerSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	var del, add int
	for i, a := range acts {
		switch {
		case strings.Contains(a.Display, "ip link del wgs0"):
			del = i + 1
		case strings.Contains(a.Display, "ip link add wgs0"):
			add = i + 1
		}
	}
	if del == 0 {
		t.Fatalf("nothing clears a device left in the host namespace, so `ip link add` will fail forever:\n%s",
			displays(acts))
	}
	if add == 0 || del > add {
		t.Errorf("the clear must come before the create, got del=%d add=%d:\n%s", del, add, displays(acts))
	}
}

// The prober resolves where the clients resolve: the list the controller writes
// into client configs, not the gateway by assumption. On a master without its own
// resolver the gateway answers nothing, and a prober pointed there reported the
// namespace broken while every real client resolved fine (on the stand).
func TestProberResolvesWhereClientsResolve(t *testing.T) {
	cw := domain.ClientWGSpec{ServerAddress: "10.80.0.1"}
	if got := proberResolvers(cw); len(got) != 1 || got[0] != "10.80.0.1" {
		t.Fatalf("no client DNS list: want the gateway, got %v", got)
	}
	cw.DNS = []string{"192.168.105.11", " 192.168.105.11 ", "192.168.105.12"}
	if got := proberResolvers(cw); strings.Join(got, ",") != "192.168.105.11,192.168.105.12" {
		t.Fatalf("client DNS list set: want it, deduplicated, got %v", got)
	}

	dir := t.TempDir()
	spec := synthPlannerSpec()
	spec.Master.ClientWG.DNS = []string{"192.168.105.11"}
	p := synthPlanner{confPath: dir + "/synth.conf", resolvPath: dir + "/resolv.conf", serverPub: "SRV",
		synthKey: wg.KeyPair{PrivateKey: "priv", PublicKey: "PUB"}}
	eng := reconcile.NewEngine(nil, p)
	_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
	b, _ := os.ReadFile(dir + "/resolv.conf")
	if !strings.Contains(string(b), "nameserver 192.168.105.11") || strings.Contains(string(b), "10.80.0.1") {
		t.Fatalf("resolv.conf must carry the clients' resolver and not the gateway:\n%s", b)
	}
}
