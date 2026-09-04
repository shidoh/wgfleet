package master

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The TPROXY listener needs the same self-heal the redirect listener has.
//
// Client UDP is handed to a transparent socket now, and TPROXY to a socket that is
// not there DROPS the datagram. So a lost UDP bind is silent client-side breakage —
// exactly the shape the redirect planner exists to catch on TCP — and nothing was
// watching it: the probe read `ss -ltnH`, which is TCP only.
func TestMihomoRedirPlannerRebindsOnALostTProxyListener(t *testing.T) {
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{BindAddress: "10.80.0.1"}}

	// TCP up, UDP down ⇒ restart.
	p := mihomoRedirPlanner{
		compose:      "/etc/wgfleet/docker-compose.yml",
		listening:    func(string) bool { return true },
		udpListening: func(string) bool { return false },
		localUp:      func(string) bool { return true },
	}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var restarts bool
	var dump string
	for _, a := range acts {
		dump += a.Summary + " | " + a.Display + "\n"
		if a.Changes() {
			restarts = true
		}
	}
	if !restarts {
		t.Errorf("a lost tproxy listener did not trigger a rebind; client UDP is dropped in silence:\n%s", dump)
	}
	if !strings.Contains(dump, "7896") {
		t.Errorf("the plan does not name the transparent port:\n%s", dump)
	}

	// Both up ⇒ quiet.
	p.udpListening = func(string) bool { return true }
	acts2, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts2 {
		if a.Changes() {
			t.Errorf("both listeners up must be quiet, got %q", a.Summary)
		}
	}
}

// A spec mihomo cannot render must defer THIS component, not abort the pass.
//
// The engine stops at the first planner error and this planner runs ahead of the
// master NAT, DOCKER-USER, blocky and the VLESS inbound. So "every exit is drained"
// — a condition the controller can produce and the node cannot fix — used to stop
// the master converging its own firewall. A master that rebooted in that state came
// back with no client DNAT, no TPROXY and no masquerade, and the self-heal branches
// written for exactly that never got to run.
func TestMihomoPlannerDefersInsteadOfAbortingThePass(t *testing.T) {
	p := mihomoPlanner{paths: PathsUnder(t.TempDir()), privateKey: "k"}
	// No exit tunnels at all: RenderConfig refuses this, by design.
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{BindAddress: "10.80.0.1"}}

	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() = %v; an unrenderable spec must not fail the pass", err)
	}
	var dump string
	for _, a := range acts {
		dump += a.Summary + "\n"
		if a.Changes() {
			t.Errorf("a deferred pass must change nothing, got %q", a.Summary)
		}
	}
	if !strings.Contains(dump, "keeping the last-good config") {
		t.Errorf("the deferral does not say why:\n%s", dump)
	}
}

// The probing phase must be bounded as a WHOLE, not per member.
//
// Every 10th pass three phases coincide — the tier decision, the warm probe of the
// inactive tier and the standby-transport sweep — which on the live fleet is 11
// members probed back to back. Each is bounded only by its own 8s timeout, so a
// blocked probe destination costs 88s against a 30s reconcile interval, and the
// status report that feeds WgfleetNodeReportStale (critical at 180s) starts
// sliding behind. A member-sized bound is not a bound on the pass.
func TestMihomoPlannerBoundsTheWholeProbingPhase(t *testing.T) {
	// A Clash API that accepts and never answers: every probe runs its full timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c // held open, never answered
		}
	}()

	p := mihomoPlanner{
		paths:       PathsUnder(t.TempDir()),
		privateKey:  "k",
		tier:        NewTierSelector(nil),
		probeBudget: 100 * time.Millisecond,
	}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{
		BindAddress:        "10.80.0.1",
		ExternalController: ln.Addr().String(),
		ExitTunnels: []domain.ExitTunnel{
			{Name: "e1", Endpoint: "203.0.113.1:51820", ServerPublicKey: "k1", TunnelIP: "10.81.0.2", MTU: 1360},
			{Name: "e2", Endpoint: "203.0.113.2:51820", ServerPublicKey: "k2", TunnelIP: "10.82.0.2", MTU: 1360},
			{Name: "e3", Endpoint: "203.0.113.3:51820", ServerPublicKey: "k3", TunnelIP: "10.83.0.2", MTU: 1360, Reserve: true},
		},
	}}

	start := time.Now()
	if _, err := p.Plan(context.Background(), spec); err != nil {
		t.Fatalf("Plan() = %v", err)
	}
	elapsed := time.Since(start)
	// The phase must actually have RUN. Without this the test passes when the spec
	// happens to skip probing entirely, which is how a test that cannot fail looks.
	if elapsed < p.probeBudget {
		t.Fatalf("the probing phase finished in %v, under its own %v budget — it never ran",
			elapsed.Truncate(time.Millisecond), p.probeBudget)
	}
	// Generous ceiling: the assertion is "bounded by the budget", not "fast". Without
	// a phase budget this takes one probeTimeout (8s) per member.
	if elapsed > 3*time.Second {
		t.Errorf("the probing phase ran %v with a %v budget — it is not bounded as a phase",
			elapsed.Truncate(time.Millisecond), p.probeBudget)
	}
}
