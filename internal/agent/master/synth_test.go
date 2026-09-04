package master

import (
	"context"
	"errors"
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
// order. Verified on the stand 2026-09-04: a WireGuard device keeps its UDP socket
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
