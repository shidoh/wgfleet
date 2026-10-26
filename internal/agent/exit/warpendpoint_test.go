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
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/egress"
)

var t0 = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

const testBoot = "boot-a"

func testWARPConfig() *egress.WARPConfig {
	return &egress.WARPConfig{
		PrivateKey:    "cHJpdmF0ZS1rZXktZm9yLXRlc3RzLW9ubHktMDAwMDA9",
		Address4:      "172.16.0.2/32",
		PeerPublicKey: "Y2xvdWRmbGFyZS13YXJwLXB1YmtleS1iYXNlNjQ9",
		Endpoint:      egress.DefaultWARPEndpoint,
	}
}

// fakeWG is the test's view of wgcf: the clock and the latest handshake, both
// movable between passes.
type fakeWG struct {
	now       time.Time
	handshake time.Time
	err       error
}

func endpointPlanner(t *testing.T, wg *fakeWG) warpEndpointPlanner {
	t.Helper()
	return warpEndpointPlanner{
		statePath: filepath.Join(t.TempDir(), "warp-endpoint.json"),
		wgcfPath:  "/etc/wireguard/wgcf.conf",
		warp:      testWARPConfig(),
		now:       func() time.Time { return wg.now },
		bootID:    func() string { return testBoot },
		handshake: func(context.Context, string) (time.Time, error) { return wg.handshake, wg.err },
	}
}

// pass plans one reconcile pass and runs whatever it planned.
func pass(t *testing.T, p warpEndpointPlanner) []reconcile.Action {
	t.Helper()
	report, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), warpSpec(), reconcile.ModeApply)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var acts []reconcile.Action
	for _, plan := range report.Plans {
		acts = append(acts, plan.Actions...)
	}
	return acts
}

func changed(acts []reconcile.Action) bool {
	for _, a := range acts {
		if a.Changes() {
			return true
		}
	}
	return false
}

func endpointOf(t *testing.T, p warpEndpointPlanner) string {
	t.Helper()
	return pickedWARPEndpoint(p.warp.Endpoint, p.statePath)
}

// runFor advances the clock pass by pass (30 s apart, as the agent does)
// for d, and reports the endpoint after every pass.
func runFor(t *testing.T, p warpEndpointPlanner, wg *fakeWG, d time.Duration) []string {
	t.Helper()
	var seen []string
	for end := wg.now.Add(d); !wg.now.After(end); wg.now = wg.now.Add(30 * time.Second) {
		pass(t, p)
		seen = append(seen, endpointOf(t, p))
	}
	return seen
}

func TestWARPEndpointCandidatesStartWithTheProfile(t *testing.T) {
	got := warpEndpointCandidates(egress.DefaultWARPEndpoint)
	want := []string{
		"engage.cloudflareclient.com:2408",
		"engage.cloudflareclient.com:500",
		"engage.cloudflareclient.com:1701",
		"engage.cloudflareclient.com:4500",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("candidates = %v, want %v", got, want)
	}
	if custom := warpEndpointCandidates("162.159.195.1:2408"); custom[0] != "162.159.195.1:2408" || len(custom) != 5 {
		t.Errorf("a custom profile endpoint goes first, then Cloudflare's ports: %v", custom)
	}
	if got := warpEndpointCandidates(""); got[0] != egress.DefaultWARPEndpoint || len(got) != 4 {
		t.Errorf("an empty profile endpoint means the default: %v", got)
	}
}

// The anti-flap guarantee. A live tunnel's latest handshake can age to ~3.5 min
// when Cloudflare initiated the last one (our side rekeys only after the keypair
// expires at 180 s). Anything under the stale bound, held for a whole day, must
// neither move the tunnel nor write a thing.
func TestWARPEndpointLiveTunnelIsNeverMoved(t *testing.T) {
	for _, age := range []time.Duration{10 * time.Second, 2 * time.Minute, 3*time.Minute + 30*time.Second, warpEndpointStaleAfter - time.Second} {
		wg := &fakeWG{now: t0}
		p := endpointPlanner(t, wg)
		for range 24 * 120 {
			wg.handshake = wg.now.Add(-age)
			if acts := pass(t, p); changed(acts) {
				t.Fatalf("handshake %s old: a live tunnel must plan nothing, got %+v", age, acts)
			}
			wg.now = wg.now.Add(30 * time.Second)
		}
		if _, err := os.Stat(p.statePath); err == nil {
			t.Errorf("handshake %s old: no state may be written for a live tunnel", age)
		}
	}
}

// A dead endpoint is left after a full window of OBSERVED silence and the next
// one is tried; the tunnel is not moved before.
func TestWARPEndpointMovesAfterAWindowOfObservedSilence(t *testing.T) {
	wg := &fakeWG{now: t0} // fresh interface, no handshake yet
	p := endpointPlanner(t, wg)

	seen := runFor(t, p, wg, warpEndpointWindow-30*time.Second)
	for _, ep := range seen {
		if ep != egress.DefaultWARPEndpoint {
			t.Fatalf("moved inside the first window: %v", seen)
		}
	}
	runFor(t, p, wg, 30*time.Second)
	if got := endpointOf(t, p); got != "engage.cloudflareclient.com:500" {
		t.Fatalf("after a full window of silence: %s, want :500", got)
	}
}

// The window counts from when the agent first SAW the silence, not from when it
// started: a wgcf bounced for another reason (MTU change, regenerated profile)
// on a long-running agent comes back with no handshake and gets a full window.
func TestWARPEndpointBouncedInterfaceGetsAFullWindow(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	for range 10 * 120 { // ten hours of a live tunnel
		wg.handshake = wg.now.Add(-time.Minute)
		pass(t, p)
		wg.now = wg.now.Add(30 * time.Second)
	}

	wg.handshake = time.Time{} // wg-quick down/up: the new interface has none yet
	pass(t, p)
	wg.now = wg.now.Add(30 * time.Second)
	pass(t, p)
	if got := endpointOf(t, p); got != egress.DefaultWARPEndpoint {
		t.Fatalf("a just-bounced interface was moved to %s 30 s later", got)
	}
}

// A handshake that went stale only starts the watch; the move comes a full
// window later.
func TestWARPEndpointStaleHandshakeStartsTheWatch(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	wg.handshake = t0.Add(-warpEndpointStaleAfter)

	pass(t, p)
	if got := endpointOf(t, p); got != egress.DefaultWARPEndpoint {
		t.Fatalf("first stale observation moved the tunnel to %s", got)
	}
	st, ok := readWARPEndpointState(p.statePath)
	if !ok || !st.SilentSince.Equal(t0) {
		t.Fatalf("first stale observation must record when the silence was seen: %+v", st)
	}
	wg.now = t0.Add(warpEndpointWindow)
	pass(t, p)
	if got := endpointOf(t, p); got != "engage.cloudflareclient.com:500" {
		t.Fatalf("a window after the stale observation: %s, want :500", got)
	}
}

// Silence recorded before a reboot does not count after it: the new boot
// watches from scratch, whatever the clock says.
func TestWARPEndpointSilenceFromAnotherBootIsIgnored(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, warpEndpointState{Endpoint: egress.DefaultWARPEndpoint, SilentSince: t0.Add(-time.Hour), BootID: "boot-old"})

	pass(t, p)
	if got := endpointOf(t, p); got != egress.DefaultWARPEndpoint {
		t.Fatalf("silence from another boot moved the tunnel to %s", got)
	}
}

// A silence stamped in the future (clock stepped back) is clamped to now.
func TestWARPEndpointFutureSilenceIsClamped(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, warpEndpointState{Endpoint: egress.DefaultWARPEndpoint, SilentSince: t0.Add(48 * time.Hour), BootID: testBoot})

	runFor(t, p, wg, warpEndpointWindow)
	if got := endpointOf(t, p); got != "engage.cloudflareclient.com:500" {
		t.Fatalf("a future-stamped silence must not hold a dead tunnel for days: %s", got)
	}
}

// The handshake is read again just before the move is written: one that came
// back between plan and apply cancels the move.
func TestWARPEndpointMoveIsCancelledByALateHandshake(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, warpEndpointState{Endpoint: egress.DefaultWARPEndpoint, SilentSince: t0.Add(-warpEndpointWindow), BootID: testBoot})

	reads := 0
	p.handshake = func(context.Context, string) (time.Time, error) {
		reads++
		if reads == 1 {
			return time.Time{}, nil // plan: still silent
		}
		return t0, nil // apply: it just handshook
	}
	pass(t, p)
	if got := endpointOf(t, p); got != egress.DefaultWARPEndpoint {
		t.Fatalf("a handshake that came back before the write must cancel the move, moved to %s", got)
	}
}

// Once every endpoint has failed, each further round waits twice as long, up to
// a cap: a Cloudflare-wide or uplink outage must not bounce wgcf every few minutes.
func TestWARPEndpointBacksOffAfterAFullRound(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, warpEndpointState{Endpoint: "engage.cloudflareclient.com:4500", SilentSince: t0.Add(-warpEndpointWindow), BootID: testBoot})

	pass(t, p)
	st, _ := readWARPEndpointState(p.statePath)
	if st.Endpoint != egress.DefaultWARPEndpoint || st.Rounds != 1 {
		t.Fatalf("after a full round: %+v, want the first candidate and round 1", st)
	}
	wg.now = wg.now.Add(30 * time.Second)
	runFor(t, p, wg, 2*warpEndpointWindow-time.Minute)
	if got := endpointOf(t, p); got != egress.DefaultWARPEndpoint {
		t.Fatalf("round 1 must wait twice the window, moved to %s", got)
	}
	runFor(t, p, wg, time.Minute)
	if got := endpointOf(t, p); got != "engage.cloudflareclient.com:500" {
		t.Fatalf("round 1 must move after twice the window: %s", got)
	}
	if got := warpEndpointDwell(20); got != warpEndpointMaxDwell {
		t.Errorf("dwell is capped: got %s, want %s", got, warpEndpointMaxDwell)
	}
}

// A handshake on a fallback keeps it and clears the watch and the back-off,
// without moving anything back.
func TestWARPEndpointHandshakeClearsTheWatch(t *testing.T) {
	wg := &fakeWG{now: t0, handshake: t0.Add(-10 * time.Second)}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, warpEndpointState{Endpoint: "engage.cloudflareclient.com:1701", SilentSince: t0.Add(-time.Minute), Rounds: 3, BootID: testBoot})

	pass(t, p)
	st, _ := readWARPEndpointState(p.statePath)
	if st.Endpoint != "engage.cloudflareclient.com:1701" || st.Rounds != 0 || !st.SilentSince.IsZero() {
		t.Errorf("state = %+v, want the same endpoint, no watch, no rounds", st)
	}
	if acts := pass(t, p); changed(acts) {
		t.Errorf("a cleared, live state must plan nothing on the next pass, got %+v", acts)
	}
}

// Not knowing is not a reason to move, and not a reason to keep counting: a
// failed `wg show` forgets the watch, so the interface's return starts afresh.
func TestWARPEndpointUnreadableHandshakeForgetsTheWatch(t *testing.T) {
	wg := &fakeWG{now: t0, err: errors.New("no such device")}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, warpEndpointState{Endpoint: egress.DefaultWARPEndpoint, SilentSince: t0.Add(-time.Hour), BootID: testBoot})

	pass(t, p)
	if got := endpointOf(t, p); got != egress.DefaultWARPEndpoint {
		t.Fatalf("an unreadable handshake moved the tunnel to %s", got)
	}
	if st, _ := readWARPEndpointState(p.statePath); !st.SilentSince.IsZero() {
		t.Errorf("the watch must be forgotten while the handshake is unreadable: %+v", st)
	}
	if acts := pass(t, p); changed(acts) {
		t.Errorf("nothing to forget twice, got %+v", acts)
	}
}

// An empty profile endpoint is the default one: the first move goes to :500,
// not a no-op "move" to the same address that burns a round.
func TestWARPEndpointEmptyProfileStartsAtTheDefault(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	p.warp.Endpoint = ""
	writeState(t, p.statePath, warpEndpointState{SilentSince: t0.Add(-warpEndpointWindow), BootID: testBoot})

	pass(t, p)
	st, _ := readWARPEndpointState(p.statePath)
	if st.Endpoint != "engage.cloudflareclient.com:500" || st.Rounds != 0 {
		t.Errorf("state = %+v, want :500 in round 0", st)
	}
}

func TestWARPEndpointIdleOffWARP(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	acts, err := p.Plan(context.Background(), domain.NodeSpec{Egress: domain.EgressDirect})
	if err != nil || changed(acts) {
		t.Fatalf("WARP not in the chain: nothing to do, got %+v err=%v", acts, err)
	}
	p.warp = nil
	acts, err = p.Plan(context.Background(), warpSpec())
	if err != nil || changed(acts) {
		t.Fatalf("WARP not registered yet: nothing to do, got %+v err=%v", acts, err)
	}
}

// Plan alone (dry-run) writes nothing.
func TestWARPEndpointPlanIsReadOnly(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), warpSpec(), reconcile.ModePlan); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if _, err := os.Stat(p.statePath); err == nil {
		t.Error("a dry run wrote the state file")
	}
}

// The WARP planner renders the endpoint the fallback picked, and without a pick
// renders exactly what it always did, so the rollout restarts no healthy tunnel.
func TestWARPPlannerRendersThePickedEndpoint(t *testing.T) {
	paths := testPaths(t)
	spec, _ := exitSpec(t)
	render := func() string {
		eng := reconcile.NewEngine(nil, warpPlanner{path: paths.WGCF, warp: testWARPConfig(), endpointState: paths.WARPEndpointState})
		_, _ = eng.Reconcile(context.Background(), spec, reconcile.ModeApply)
		data, err := os.ReadFile(paths.WGCF)
		if err != nil {
			t.Fatalf("wgcf.conf not written: %v", err)
		}
		return string(data)
	}

	if got := render(); !strings.Contains(got, "Endpoint = engage.cloudflareclient.com:2408\n") {
		t.Errorf("no pick: the profile endpoint, got:\n%s", got)
	}
	writeState(t, paths.WARPEndpointState, warpEndpointState{Endpoint: "engage.cloudflareclient.com:4500"})
	if got := render(); !strings.Contains(got, "Endpoint = engage.cloudflareclient.com:4500\n") {
		t.Errorf("picked :4500, got:\n%s", got)
	}
	writeState(t, paths.WARPEndpointState, warpEndpointState{Endpoint: "evil.example:53"})
	if got := render(); !strings.Contains(got, "Endpoint = engage.cloudflareclient.com:2408\n") {
		t.Errorf("a pick outside the candidates is ignored, got:\n%s", got)
	}
}

func TestParseWGHandshake(t *testing.T) {
	cases := []struct {
		out  string
		want time.Time
	}{
		{"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\t1793027622\n", time.Unix(1793027622, 0)},
		{"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\t0\n", time.Time{}},
		{"", time.Time{}},
	}
	for _, c := range cases {
		if got := parseWGHandshake(c.out); !got.Equal(c.want) {
			t.Errorf("parseWGHandshake(%q) = %v, want %v", c.out, got, c.want)
		}
	}
}

func writeState(t *testing.T, path string, st warpEndpointState) {
	t.Helper()
	if err := writeWARPEndpointState(path, st); err != nil {
		t.Fatalf("write state: %v", err)
	}
}
