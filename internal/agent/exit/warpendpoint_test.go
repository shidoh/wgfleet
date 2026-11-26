package exit

import (
	"context"
	"errors"
	"net/netip"
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
	family    domain.WARPIPFamily
	// noV4/noV6 make the resolver fail for that family.
	noV4, noV6 bool
}

const (
	cfV4 = "162.159.192.1"
	cfV6 = "2606:4700:d0::a29f:c001"
)

// Candidate keys and the endpoints they render, as the tests see them.
const (
	v4Key2408  = "ipv4 engage.cloudflareclient.com:2408"
	v4Key500   = "ipv4 engage.cloudflareclient.com:500"
	v4Key4500  = "ipv4 engage.cloudflareclient.com:4500"
	v6Key2408  = "ipv6 engage.cloudflareclient.com:2408"
	nameKey    = "engage.cloudflareclient.com:2408"
	v4Ep2408   = cfV4 + ":2408"
	v4Ep500    = cfV4 + ":500"
	v4Ep4500   = cfV4 + ":4500"
	v6Ep2408   = "[" + cfV6 + "]:2408"
	nameEp2408 = "engage.cloudflareclient.com:2408"
)

func (wg *fakeWG) lookup(_ context.Context, network, host string) ([]netip.Addr, error) {
	if host != "engage.cloudflareclient.com" {
		return nil, errors.New("no such host")
	}
	switch {
	case network == "ip4" && !wg.noV4:
		return []netip.Addr{netip.MustParseAddr(cfV4)}, nil
	case network == "ip6" && !wg.noV6:
		return []netip.Addr{netip.MustParseAddr(cfV6)}, nil
	}
	return nil, errors.New("no address of that family")
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
		lookup:    wg.lookup,
	}
}

// adopted is the state after the first pass on a fresh node: the first IPv4
// candidate, no watch.
func adopted() warpEndpointState {
	return warpEndpointState{Candidate: v4Key2408, Endpoint: v4Ep2408, BootID: testBoot}
}

// pass plans one reconcile pass and runs whatever it planned.
func pass(t *testing.T, p warpEndpointPlanner, family ...domain.WARPIPFamily) []reconcile.Action {
	t.Helper()
	spec := warpSpec()
	if len(family) > 0 {
		spec.WARPIPFamily = family[0]
	}
	report, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), spec, reconcile.ModeApply)
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

func endpointOf(t *testing.T, p warpEndpointPlanner, family ...domain.WARPIPFamily) string {
	t.Helper()
	var f domain.WARPIPFamily
	if len(family) > 0 {
		f = family[0]
	}
	return pickedWARPEndpoint(p.warp.Endpoint, f, p.statePath)
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

func candidateKeys(cs []warpCandidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.key())
	}
	return out
}

func TestWARPEndpointCandidatesByFamily(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		family  domain.WARPIPFamily
		want    []string
	}{
		{"auto: IPv4, then IPv6, then the name", egress.DefaultWARPEndpoint, "", []string{
			"ipv4 engage.cloudflareclient.com:2408", "ipv4 engage.cloudflareclient.com:500",
			"ipv4 engage.cloudflareclient.com:1701", "ipv4 engage.cloudflareclient.com:4500",
			"ipv6 engage.cloudflareclient.com:2408", "ipv6 engage.cloudflareclient.com:500",
			"ipv6 engage.cloudflareclient.com:1701", "ipv6 engage.cloudflareclient.com:4500",
			"engage.cloudflareclient.com:2408",
		}},
		{"ipv4 only", egress.DefaultWARPEndpoint, domain.WARPIPFamilyIPv4, []string{
			"ipv4 engage.cloudflareclient.com:2408", "ipv4 engage.cloudflareclient.com:500",
			"ipv4 engage.cloudflareclient.com:1701", "ipv4 engage.cloudflareclient.com:4500",
		}},
		{"ipv6 only", egress.DefaultWARPEndpoint, domain.WARPIPFamilyIPv6, []string{
			"ipv6 engage.cloudflareclient.com:2408", "ipv6 engage.cloudflareclient.com:500",
			"ipv6 engage.cloudflareclient.com:1701", "ipv6 engage.cloudflareclient.com:4500",
		}},
		{"the profile's port goes first", "engage.cloudflareclient.com:500", domain.WARPIPFamilyIPv4, []string{
			"ipv4 engage.cloudflareclient.com:500", "ipv4 engage.cloudflareclient.com:2408",
			"ipv4 engage.cloudflareclient.com:1701", "ipv4 engage.cloudflareclient.com:4500",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := candidateKeys(warpEndpointCandidates(c.profile, c.family)); strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("candidates = %v, want %v", got, c.want)
			}
		})
	}
	if custom := warpEndpointCandidates("162.159.195.1:2408", ""); custom[0].key() != "162.159.195.1:2408" || len(custom) != 9 {
		t.Errorf("auto: a custom profile endpoint goes first, then both families: %v", candidateKeys(custom))
	}
	if got := warpEndpointCandidates("", ""); got[len(got)-1].key() != egress.DefaultWARPEndpoint {
		t.Errorf("an empty profile endpoint means the default: %v", candidateKeys(got))
	}
}

// A host whose name resolves AAAA-first and whose IPv6 goes nowhere gets no
// WARP handshake by name, ever. The first pass must put wgcf on an IPv4
// address, whatever the state an older agent left behind.
func TestWARPEndpointFirstPassPicksIPv4OverTheName(t *testing.T) {
	for _, old := range []warpEndpointState{
		{},
		{Endpoint: "engage.cloudflareclient.com:500", SilentSince: t0.Add(-time.Hour), Rounds: 22, BootID: testBoot},
	} {
		wg := &fakeWG{now: t0}
		p := endpointPlanner(t, wg)
		if old.Endpoint != "" {
			writeState(t, p.statePath, old)
		}
		pass(t, p)
		if got := endpointOf(t, p); got != v4Ep2408 {
			t.Errorf("state %+v: first pass renders %s, want %s", old, got, v4Ep2408)
		}
		st, _ := readWARPEndpointState(p.statePath)
		if st.watching() || st.Rounds != 0 {
			t.Errorf("state %+v: the first pick starts clean, got %+v", old, st)
		}
	}
}

func TestWARPEndpointPinnedFamilyRendersOnlyThatFamily(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	pass(t, p, domain.WARPIPFamilyIPv6)
	if got := endpointOf(t, p, domain.WARPIPFamilyIPv6); got != v6Ep2408 {
		t.Fatalf("ipv6 pinned: %s, want %s", got, v6Ep2408)
	}
	// The same state read under ipv4 is not a pick: the render falls back to the
	// profile until the planner picks again.
	if got := endpointOf(t, p, domain.WARPIPFamilyIPv4); got != nameEp2408 {
		t.Errorf("an IPv6 pick under ipv4: %s, want the profile", got)
	}
	pass(t, p, domain.WARPIPFamilyIPv4)
	if got := endpointOf(t, p, domain.WARPIPFamilyIPv4); got != v4Ep2408 {
		t.Errorf("switching the knob to ipv4 repicks: %s, want %s", got, v4Ep2408)
	}
}

// A candidate that does not resolve is skipped: no IPv4 address ⇒ IPv6.
func TestWARPEndpointUnresolvableFamilyIsSkipped(t *testing.T) {
	wg := &fakeWG{now: t0, noV4: true}
	p := endpointPlanner(t, wg)
	pass(t, p)
	if got := endpointOf(t, p); got != v6Ep2408 {
		t.Fatalf("no A record: %s, want %s", got, v6Ep2408)
	}

	// Nothing resolves at all: auto still has the name.
	wg2 := &fakeWG{now: t0, noV4: true, noV6: true}
	p2 := endpointPlanner(t, wg2)
	pass(t, p2)
	if got := endpointOf(t, p2); got != nameEp2408 {
		t.Errorf("resolver down: %s, want the name", got)
	}

	// Pinned ipv4 with no IPv4 address: no pick is written, the profile stays.
	wg3 := &fakeWG{now: t0, noV4: true}
	p3 := endpointPlanner(t, wg3)
	pass(t, p3, domain.WARPIPFamilyIPv4)
	if _, err := os.Stat(p3.statePath); err == nil {
		t.Errorf("pinned ipv4 without an IPv4 address must not write a pick")
	}
}

// The anti-flap guarantee. A live tunnel's latest handshake can age to ~3.5 min
// when Cloudflare initiated the last one (our side rekeys only after the keypair
// expires at 180 s). Anything under the stale bound, held for a whole day, must
// neither move the tunnel nor write a thing once it has a pick.
func TestWARPEndpointLiveTunnelIsNeverMoved(t *testing.T) {
	for _, age := range []time.Duration{10 * time.Second, 2 * time.Minute, 3*time.Minute + 30*time.Second, warpEndpointStaleAfter - time.Second} {
		wg := &fakeWG{now: t0}
		p := endpointPlanner(t, wg)
		writeState(t, p.statePath, adopted())
		for range 24 * 120 {
			wg.handshake = wg.now.Add(-age)
			if acts := pass(t, p); changed(acts) {
				t.Fatalf("handshake %s old: a live tunnel must plan nothing, got %+v", age, acts)
			}
			wg.now = wg.now.Add(30 * time.Second)
		}
	}
}

// A dead endpoint is left after a full window of OBSERVED silence and the next
// one is tried; the tunnel is not moved before.
func TestWARPEndpointMovesAfterAWindowOfObservedSilence(t *testing.T) {
	wg := &fakeWG{now: t0} // fresh interface, no handshake yet
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, adopted())

	seen := runFor(t, p, wg, warpEndpointWindow-30*time.Second)
	for _, ep := range seen {
		if ep != v4Ep2408 {
			t.Fatalf("moved inside the first window: %v", seen)
		}
	}
	runFor(t, p, wg, 30*time.Second)
	if got := endpointOf(t, p); got != v4Ep500 {
		t.Fatalf("after a full window of silence: %s, want %s", got, v4Ep500)
	}
}

// After every IPv4 port has failed, auto moves to IPv6.
func TestWARPEndpointAutoFallsThroughToIPv6(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, warpEndpointState{Candidate: v4Key4500, Endpoint: v4Ep4500, SilentSince: t0.Add(-warpEndpointWindow), BootID: testBoot})
	pass(t, p)
	st, _ := readWARPEndpointState(p.statePath)
	if st.Candidate != v6Key2408 || st.Endpoint != v6Ep2408 || st.Rounds != 0 {
		t.Errorf("after the last IPv4 port: %+v, want %s in round 0", st, v6Key2408)
	}
}

// The window counts from when the agent first SAW the silence, not from when it
// started: a wgcf bounced for another reason (MTU change, regenerated profile)
// on a long-running agent comes back with no handshake and gets a full window.
func TestWARPEndpointBouncedInterfaceGetsAFullWindow(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, adopted())
	for range 10 * 120 { // ten hours of a live tunnel
		wg.handshake = wg.now.Add(-time.Minute)
		pass(t, p)
		wg.now = wg.now.Add(30 * time.Second)
	}

	wg.handshake = time.Time{} // wg-quick down/up: the new interface has none yet
	pass(t, p)
	wg.now = wg.now.Add(30 * time.Second)
	pass(t, p)
	if got := endpointOf(t, p); got != v4Ep2408 {
		t.Fatalf("a just-bounced interface was moved to %s 30 s later", got)
	}
}

// A handshake that went stale only starts the watch; the move comes a full
// window later.
func TestWARPEndpointStaleHandshakeStartsTheWatch(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, adopted())
	wg.handshake = t0.Add(-warpEndpointStaleAfter)

	pass(t, p)
	if got := endpointOf(t, p); got != v4Ep2408 {
		t.Fatalf("first stale observation moved the tunnel to %s", got)
	}
	st, ok := readWARPEndpointState(p.statePath)
	if !ok || !st.SilentSince.Equal(t0) {
		t.Fatalf("first stale observation must record when the silence was seen: %+v", st)
	}
	wg.now = t0.Add(warpEndpointWindow)
	pass(t, p)
	if got := endpointOf(t, p); got != v4Ep500 {
		t.Fatalf("a window after the stale observation: %s, want %s", got, v4Ep500)
	}
}

// Silence recorded before a reboot does not count after it: the new boot
// watches from scratch, whatever the clock says.
func TestWARPEndpointSilenceFromAnotherBootIsIgnored(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	st := adopted()
	st.SilentSince, st.BootID = t0.Add(-time.Hour), "boot-old"
	writeState(t, p.statePath, st)

	pass(t, p)
	if got := endpointOf(t, p); got != v4Ep2408 {
		t.Fatalf("silence from another boot moved the tunnel to %s", got)
	}
}

// A silence stamped in the future (clock stepped back) is clamped to now.
func TestWARPEndpointFutureSilenceIsClamped(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	st := adopted()
	st.SilentSince = t0.Add(48 * time.Hour)
	writeState(t, p.statePath, st)

	runFor(t, p, wg, warpEndpointWindow)
	if got := endpointOf(t, p); got != v4Ep500 {
		t.Fatalf("a future-stamped silence must not hold a dead tunnel for days: %s", got)
	}
}

// The handshake is read again just before the move is written: one that came
// back between plan and apply cancels the move.
func TestWARPEndpointMoveIsCancelledByALateHandshake(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	st := adopted()
	st.SilentSince = t0.Add(-warpEndpointWindow)
	writeState(t, p.statePath, st)

	reads := 0
	p.handshake = func(context.Context, string) (time.Time, error) {
		reads++
		if reads == 1 {
			return time.Time{}, nil // plan: still silent
		}
		return t0, nil // apply: it just handshook
	}
	pass(t, p)
	if got := endpointOf(t, p); got != v4Ep2408 {
		t.Fatalf("a handshake that came back before the write must cancel the move, moved to %s", got)
	}
}

// Once every endpoint has failed, each further round waits twice as long, up to
// a cap: a Cloudflare-wide or uplink outage must not bounce wgcf every few minutes.
func TestWARPEndpointBacksOffAfterAFullRound(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	writeState(t, p.statePath, warpEndpointState{Candidate: nameKey, Endpoint: nameEp2408, SilentSince: t0.Add(-warpEndpointWindow), BootID: testBoot})

	pass(t, p)
	st, _ := readWARPEndpointState(p.statePath)
	if st.Candidate != v4Key2408 || st.Rounds != 1 {
		t.Fatalf("after a full round: %+v, want the first candidate and round 1", st)
	}
	wg.now = wg.now.Add(30 * time.Second)
	runFor(t, p, wg, 2*warpEndpointWindow-time.Minute)
	if got := endpointOf(t, p); got != v4Ep2408 {
		t.Fatalf("round 1 must wait twice the window, moved to %s", got)
	}
	runFor(t, p, wg, time.Minute)
	if got := endpointOf(t, p); got != v4Ep500 {
		t.Fatalf("round 1 must move after twice the window: %s", got)
	}
	if st, _ := readWARPEndpointState(p.statePath); st.Rounds != 1 {
		t.Errorf("a move inside a round keeps the round count: %+v", st)
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
	writeState(t, p.statePath, warpEndpointState{Candidate: v6Key2408, Endpoint: v6Ep2408, SilentSince: t0.Add(-time.Minute), Rounds: 3, BootID: testBoot})

	pass(t, p)
	st, _ := readWARPEndpointState(p.statePath)
	if st.Endpoint != v6Ep2408 || st.Rounds != 0 || !st.SilentSince.IsZero() {
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
	st := adopted()
	st.SilentSince = t0.Add(-time.Hour)
	writeState(t, p.statePath, st)

	pass(t, p)
	if got := endpointOf(t, p); got != v4Ep2408 {
		t.Fatalf("an unreadable handshake moved the tunnel to %s", got)
	}
	if st, _ := readWARPEndpointState(p.statePath); !st.SilentSince.IsZero() {
		t.Errorf("the watch must be forgotten while the handshake is unreadable: %+v", st)
	}
	if acts := pass(t, p); changed(acts) {
		t.Errorf("nothing to forget twice, got %+v", acts)
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

// Plan alone (dry-run) writes nothing and resolves nothing.
func TestWARPEndpointPlanIsReadOnly(t *testing.T) {
	wg := &fakeWG{now: t0}
	p := endpointPlanner(t, wg)
	p.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Error("a dry run resolved the endpoint host")
		return nil, errors.New("unexpected")
	}
	if _, err := reconcile.NewEngine(nil, p).Reconcile(context.Background(), warpSpec(), reconcile.ModePlan); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if _, err := os.Stat(p.statePath); err == nil {
		t.Error("a dry run wrote the state file")
	}
}

// The WARP planner renders the endpoint the fallback picked, and only a pick
// that is valid for its candidate: the state file must never put anything else
// into wgcf.conf.
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
	writeState(t, paths.WARPEndpointState, warpEndpointState{Candidate: v4Key500, Endpoint: v4Ep500})
	if got := render(); !strings.Contains(got, "Endpoint = "+v4Ep500+"\n") {
		t.Errorf("picked IPv4 :500, got:\n%s", got)
	}
	writeState(t, paths.WARPEndpointState, warpEndpointState{Candidate: v6Key2408, Endpoint: v6Ep2408})
	if got := render(); !strings.Contains(got, "Endpoint = "+v6Ep2408+"\n") {
		t.Errorf("picked IPv6 :2408, got:\n%s", got)
	}
	for _, bad := range []warpEndpointState{
		{Endpoint: "engage.cloudflareclient.com:4500"},             // older agent's state: no candidate
		{Candidate: v4Key500, Endpoint: "evil.example:53"},         // not an address
		{Candidate: v4Key500, Endpoint: v6Ep2408},                  // wrong family
		{Candidate: v4Key500, Endpoint: cfV4 + ":53"},              // wrong port
		{Candidate: v4Key500, Endpoint: v4Ep500 + "\nPostUp = id"}, // injection
		{Candidate: "ipv4 evil.example:500", Endpoint: v4Ep500},    // not a candidate
	} {
		writeState(t, paths.WARPEndpointState, bad)
		if got := render(); !strings.Contains(got, "Endpoint = engage.cloudflareclient.com:2408\n") || strings.Contains(got, "PostUp") {
			t.Errorf("state %+v must be ignored, got:\n%s", bad, got)
		}
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
