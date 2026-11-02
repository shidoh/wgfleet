package master

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/reconcile"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/mihomo"
	"github.com/shidoh/wgfleet/internal/wg"
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
// inactive tier and the standby-transport sweep — which on a mid-sized fleet is a
// dozen members probed back to back. Each is bounded only by its own 8s timeout, so a
// blocked probe destination costs well over a minute against a 30s reconcile interval, and the
// status report that feeds WgfleetNodeReportStale (critical at 180s) starts
// sliding behind. A member-sized bound is not a bound on the pass.
//
// The bound is "budget plus at most ONE attempt", not "budget". The phase spends
// its budget by skipping members it has no room for, and a member already on the
// wire is always allowed to finish — cutting one short is what used to mark healthy
// exits dead inside mihomo (see TestProbingPhaseNeverAbandonsAnInFlightProbe). So
// the attempt bound is injected here too, or the one permitted attempt against a
// server that never answers would be the real 8s.
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
		paths:        PathsUnder(t.TempDir()),
		privateKey:   "k",
		tier:         NewTierSelector(nil),
		probeBudget:  100 * time.Millisecond,
		probeAttempt: 200 * time.Millisecond,
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
	// Generous ceiling: the assertion is "bounded as a phase", not "fast". Without a
	// phase budget this takes one attempt per member; with one, it is the budget plus
	// the single attempt that was allowed to run to completion.
	if elapsed > 3*time.Second {
		t.Errorf("the probing phase ran %v with a %v budget — it is not bounded as a phase",
			elapsed.Truncate(time.Millisecond), p.probeBudget)
	}
}

// Everything mihomo binds is an address on the HOST. Moved into its own namespace
// without re-pointing them, every listener fails with EADDRNOTAVAIL while the
// rules in the namespace point at ports nobody is on: TCP refused, UDP into the
// fail-closed drop. That is every client's traffic, and the branch shipped with
// internal/mihomo/render.go untouched.
func TestMihomoBindsTheNamespaceWhenItLivesThere(t *testing.T) {
	spec := domain.MasterSpec{
		BindAddress:        "10.73.0.1",
		ExternalController: "172.29.3.10:9090",
		NetnsCIDR:          "100.127.255.0/30",
		ExitTunnels: []domain.ExitTunnel{{
			Name: "exit-de-1", Endpoint: "198.51.100.7:51820",
			ServerPublicKey: "EXITPUB==", TunnelIP: "10.81.0.2", MTU: 1360,
		}},
	}
	cfg, err := mihomo.RenderConfig(mihomo.RenderInput{
		Spec: spec, PrivateKey: testKey(t), NetnsPeerAddr: "100.127.255.2",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"bind-address: 100.127.255.2",
		"external-controller: 100.127.255.2:9090",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q in the rendered config", want)
		}
	}
	// The host addresses must be gone, not merely joined: a listener on an address
	// that does not exist in this namespace fails the whole start-up.
	for _, unwanted := range []string{"bind-address: 10.73.0.1", "external-controller: 172.29.3.10:9090"} {
		if strings.Contains(cfg, unwanted) {
			t.Errorf("still binding a host address: %q", unwanted)
		}
	}
	// And the self-dial guard has to follow the bind address, or mihomo will happily
	// proxy a connection to its own redirect port.
	if !strings.Contains(cfg, "IP-CIDR,100.127.255.2/32,REJECT,no-resolve") {
		t.Error("the self-dial reject rule still names the host address")
	}
}

// On host networking nothing changes: this is the state every master is in today.
func TestMihomoKeepsHostAddressesWhenItHasNotMoved(t *testing.T) {
	spec := domain.MasterSpec{BindAddress: "10.73.0.1", ExternalController: "172.29.3.10:9090",
		ExitTunnels: []domain.ExitTunnel{{
			Name: "exit-de-1", Endpoint: "198.51.100.7:51820",
			ServerPublicKey: "EXITPUB==", TunnelIP: "10.81.0.2", MTU: 1360,
		}},
	}
	cfg, err := mihomo.RenderConfig(mihomo.RenderInput{Spec: spec, PrivateKey: testKey(t)})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(cfg, "bind-address: 10.73.0.1") ||
		!strings.Contains(cfg, "external-controller: 172.29.3.10:9090") {
		t.Errorf("an unmoved mihomo lost its host addresses:\n%s", cfg)
	}
}

// A moved bind address cannot be applied in place: a hot reload accepts it,
// reports success and re-opens nothing, so mihomo goes on listening where it was
// while the rules point at where it should be.
func TestChangedListenersForcesARestart(t *testing.T) {
	old := []byte("bind-address: 10.73.0.1\nexternal-controller: 172.29.3.10:9090\nredir-port: 7895\n")
	newer := []byte("bind-address: 100.127.255.2\nexternal-controller: 100.127.255.2:9090\nredir-port: 7895\n")
	changed := mihomo.ChangedListeners(old, newer)
	if len(changed) != 2 {
		t.Fatalf("got %v, want both the bind address and the controller", changed)
	}
	if len(mihomo.ChangedListeners(old, old)) != 0 {
		t.Error("an unchanged config was reported as needing a restart")
	}
}

// Inside the namespace, 127.0.0.1 is the NAMESPACE's loopback with nothing on it.
// blocky is on the host and binds the client gateway, which the namespace reaches
// over its route back to the client pool.
func TestResolversFollowMihomoIntoTheNamespace(t *testing.T) {
	spec := domain.NodeSpec{
		DNS:    domain.DNSFilterSpec{Enabled: true},
		Master: &domain.MasterSpec{BindAddress: "10.73.0.1"},
	}
	if got := mihomoResolvers(spec, false); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("on the host the resolver should be loopback, got %v", got)
	}
	if got := mihomoResolvers(spec, true); len(got) != 1 || got[0] != "10.73.0.1" {
		t.Errorf("in the namespace the resolver must be reachable, got %v", got)
	}
}

// The agent has to follow the API. Everything it does to mihomo goes through it:
// tier probing, hot reloads, the mihomo-api health check, the dashboard link.
func TestClashAPIAddrFollowsTheMove(t *testing.T) {
	spec := domain.NodeSpec{Master: &domain.MasterSpec{
		ExternalController: "172.29.3.10:9090",
		NetnsCIDR:          "100.127.255.0/30",
	}}
	if got := ClashAPIAddr(spec, false); got != "172.29.3.10:9090" {
		t.Errorf("unmoved: got %q", got)
	}
	if got := ClashAPIAddr(spec, true); got != "100.127.255.2:9090" {
		t.Errorf("moved: got %q, want the namespace end of the veth", got)
	}
}

// testKey mints a throwaway WireGuard private key for a render.
func testKey(t *testing.T) string {
	t.Helper()
	kp, err := wg.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return kp.PrivateKey
}

// After the move, the redirect self-heal must find mihomo where it now is.
//
// The defect this guards: the probe read the HOST's socket table for the HOST's
// bind address; mihomo was in a namespace binding another one, so the answer was
// always "listener down" and the planner restarted the container every pass. Each
// restart re-initialises mihomo's userspace WireGuard devices and knocks exits out
// of the balancer within minutes.
func TestRedirectSelfHealLooksInsideTheNamespaceOnceMoved(t *testing.T) {
	var asked []string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		asked = append(asked, line)
		switch {
		case strings.Contains(line, "docker inspect"):
			return "4242\n", nil
		case strings.Contains(line, "ip -br addr"):
			return "mih0@if8 UP 100.127.255.2/30\n", nil
		case strings.Contains(line, "ss -ltnH"):
			return "LISTEN 0 4096 100.127.255.2:7895 0.0.0.0:*\n", nil
		case strings.Contains(line, "ss -lunH"):
			return "UNCONN 0 0 100.127.255.2:7896 0.0.0.0:*\n", nil
		}
		return "", errors.New("absent: " + line)
	}
	p := mihomoRedirPlanner{
		compose:       "/etc/wgfleet/docker-compose.yml",
		netnsAttached: func() bool { return true },
		run:           run,
	}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{
		BindAddress: "10.73.0.1", NetnsCIDR: "100.127.255.0/30",
	}}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Fatalf("a healthy moved mihomo was restarted anyway: %q", a.Summary)
		}
	}
	joined := strings.Join(asked, "\n")
	if !strings.Contains(joined, "nsenter") {
		t.Errorf("the probe never entered the namespace:\n%s", joined)
	}
	if strings.Contains(joined, "10.73.0.1:7895") {
		t.Errorf("the probe still asks about the host address:\n%s", joined)
	}
}

// And when the listener really is gone in there, it still restarts — the self-heal
// must not be traded away for namespace-awareness.
func TestRedirectSelfHealStillRestartsWhenTheNamespaceListenerIsGone(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(line, "docker inspect"):
			return "4242\n", nil
		case strings.Contains(line, "ip -br addr"):
			return "mih0@if8 UP 100.127.255.2/30\n", nil
		case strings.Contains(line, "ss -"):
			return "", nil // nothing listening
		}
		return "", errors.New("absent")
	}
	p := mihomoRedirPlanner{
		compose:       "/etc/wgfleet/docker-compose.yml",
		netnsAttached: func() bool { return true },
		run:           run,
	}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{
		BindAddress: "10.73.0.1", NetnsCIDR: "100.127.255.0/30",
	}}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var restarts int
	for _, a := range acts {
		if a.Changes() {
			restarts++
		}
	}
	if restarts == 0 {
		t.Error("a genuinely lost listener in the namespace went unrepaired")
	}
}

// A holder that is not up cannot host a listener, and restarting mihomo will not
// change that — defer instead of thrashing.
func TestRedirectSelfHealDefersWhenTheHolderIsDown(t *testing.T) {
	run := func(context.Context, string, ...string) (string, error) {
		return "", errors.New("No such object: wgfleet-netns")
	}
	p := mihomoRedirPlanner{
		compose: "/x.yml", netnsAttached: func() bool { return true }, run: run,
	}
	spec := domain.NodeSpec{Role: domain.RoleMaster, Master: &domain.MasterSpec{
		BindAddress: "10.73.0.1", NetnsCIDR: "100.127.255.0/30",
	}}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range acts {
		if a.Changes() {
			t.Errorf("thrashed mihomo while its namespace holder was down: %q", a.Summary)
		}
	}
}

// The journal is the only record of why mihomo was reloaded — the previous config
// is gone the moment the file is overwritten. So the reload action has to SAY what
// moved, as key paths: a burst of reloads that each record only "update
// config.yaml" leaves the trigger impossible to find.
func TestMihomoReloadActionNamesWhatChanged(t *testing.T) {
	paths := PathsUnder(t.TempDir())
	spec := domain.NodeSpec{Master: &domain.MasterSpec{
		BindAddress: "10.73.0.1", ExternalController: "172.29.3.10:9090",
		ExitTunnels: []domain.ExitTunnel{{
			Name: "exit-de-1", Endpoint: "198.51.100.7:51820",
			ServerPublicKey: "EXITPUB==", TunnelIP: "10.81.0.2", MTU: 1360,
		}},
	}}
	p := mihomoPlanner{paths: paths, privateKey: testKey(t),
		reload:  func(context.Context, string, string, []byte) error { return nil },
		restart: func(context.Context) error { return nil }} // the first write "changes" every proxy
	// First pass writes the config; then change one thing on disk so the next
	// render differs from it in exactly that place.
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	raw, err := os.ReadFile(paths.MihomoConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "MATCH,") {
		t.Fatalf("rendered config has no MATCH rule to perturb:\n%s", raw)
	}
	edited := strings.Replace(string(raw), "MATCH,", "MATCH,DIRECT #", 1)
	if err := os.WriteFile(paths.MihomoConfig, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	acts, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var reloadSummary string
	for _, a := range acts {
		if a.Target == "mihomo" && a.Kind == reconcile.ActionUpdate {
			reloadSummary = a.Summary
		}
	}
	if reloadSummary == "" {
		t.Fatalf("no reload action in %+v", acts)
	}
	if !strings.Contains(reloadSummary, "changed: rules") {
		t.Errorf("reload does not name the changed section: %q", reloadSummary)
	}
}

// Every applied reload or restart of mihomo has to reach the agent, or the
// mover judges the namespace by a probe taken while the container was down.
func TestMihomoReloadAndRestartReportADisturbance(t *testing.T) {
	paths := PathsUnder(t.TempDir())
	spec := domain.NodeSpec{Master: &domain.MasterSpec{
		BindAddress: "10.73.0.1", ExternalController: "172.29.3.10:9090",
		ExitTunnels: []domain.ExitTunnel{{
			Name: "exit-de-1", Endpoint: "198.51.100.7:51820",
			ServerPublicKey: "EXITPUB==", TunnelIP: "10.81.0.2", MTU: 1360,
		}},
	}}
	disturbed := 0
	p := mihomoPlanner{paths: paths, privateKey: testKey(t),
		reload:    func(context.Context, string, string, []byte) error { return nil },
		restart:   func(context.Context) error { return nil },
		disturbed: func() { disturbed++ }}
	// First pass: proxies appear ⇒ restart path.
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if disturbed != 1 {
		t.Fatalf("restart did not report a disturbance (got %d)", disturbed)
	}
	// Perturb a rule ⇒ hot-reload path.
	raw, _ := os.ReadFile(paths.MihomoConfig)
	if err := os.WriteFile(paths.MihomoConfig, []byte(strings.Replace(string(raw), "MATCH,", "MATCH,DIRECT #", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if disturbed != 2 {
		t.Fatalf("hot reload did not report a disturbance (got %d)", disturbed)
	}
	// A converged pass reports nothing.
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatalf("third pass: %v", err)
	}
	if disturbed != 2 {
		t.Fatalf("a no-change pass reported a disturbance (got %d)", disturbed)
	}
	// And the self-heal restart gate reports too.
	fired := 0
	act := gateRestart(nil, func() { fired++ }, "mihomo redirect listener",
		reconcile.CustomAction(reconcile.ActionUpdate, "mihomo", "restart", "x", func(context.Context) error { return nil }))
	if _, err := reconcile.NewEngine(nil, oneAction{act}).Reconcile(context.Background(), spec, reconcile.ModeApply); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Fatalf("gated restart did not report a disturbance (got %d)", fired)
	}
}

// oneAction is a planner that returns a fixed action, for exercising hooks.
type oneAction struct{ a reconcile.Action }

func (oneAction) Component() string { return "test" }
func (o oneAction) Plan(context.Context, domain.NodeSpec) ([]reconcile.Action, error) {
	return []reconcile.Action{o.a}, nil
}
