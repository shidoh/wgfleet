package keybroker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

var errStoreDown = errors.New("disk I/O error")

// rotationReadFails is a store that cannot say which generation a pinned port is in.
type rotationReadFails struct{ store.Store }

func (rotationReadFails) GetAWGPortRotation(context.Context, string, string) (int, time.Time, error) {
	return 0, time.Time{}, errStoreDown
}

// confirmationReadFails is a store that cannot say what an exit confirmed.
type confirmationReadFails struct{ store.Store }

func (confirmationReadFails) GetAWGPinConfirmation(context.Context, string, string) (string, string, time.Time, error) {
	return "", "", time.Time{}, errStoreDown
}

// confirmationWriteFails is a store that reads but cannot record a confirmation.
type confirmationWriteFails struct{ store.Store }

func (confirmationWriteFails) SetAWGPinConfirmation(context.Context, string, string, string, string, time.Time) error {
	return errStoreDown
}

// restartedOver is a controller restart: a new Broker with nothing in memory,
// over what the old one left in the store.
func restartedOver(st store.Store, old *Broker, clock *time.Time) *Broker {
	return New(st, old.fleet, slog.New(slog.NewTextHandler(io.Discard, nil)), WithClock(func() time.Time { return *clock }))
}

func wantRenderFails(t *testing.T, b *Broker, id string) {
	t.Helper()
	_, err := b.RenderNodeSpec(context.Background(), id)
	if !errors.Is(err, errStoreDown) {
		t.Errorf("render %s: err = %v, want the store's read error — the node must keep its last-good spec", id, err)
	}
	// …and it has to say so in a way the gRPC layer can tell from a refusal: only
	// then does the agent fall back to its last good spec instead of obeying a "no".
	if !errors.Is(err, store.ErrUnreadable) {
		t.Errorf("render %s: err = %v is not marked store.ErrUnreadable", id, err)
	}
}

// Generation 0 is the port already judged poisoned. A store that cannot say which
// generation the tunnel is in must fail the render, not hand that port back.
func TestAnUnreadablePortGenerationFailsTheRender(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, st, _ := eiFleet(t, &now)
	broken := restartedOver(rotationReadFails{st}, b, &now)
	wantRenderFails(t, broken, eiExit)
	wantRenderFails(t, broken, eiMaster)
}

// The same rule for the confirmation: unreadable is not "never confirmed".
func TestAnUnreadableConfirmationFailsTheRender(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, st, _ := eiFleet(t, &now)
	broken := restartedOver(confirmationReadFails{st}, b, &now)
	wantRenderFails(t, broken, eiMaster)
}

// A confirmation that could not be written down is still a confirmation: the
// gate arms, and stays armed, on what this process saw.
func TestAConfirmationThatCannotBeStoredStillArmsTheGate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, st, _ := eiFleet(t, &now)
	flaky := restartedOver(confirmationWriteFails{st}, b, &now)
	report(t, st, eiExit, now, now, eiPinned)
	if got := masterTunnel(t, flaky).MasterAddr; got != eiPinned {
		t.Fatalf("gate = %q, want %q", got, eiPinned)
	}
	// The exit roams: only what the broker remembers holds the gate now.
	report(t, st, eiExit, now, now, eiMasterIP+":40000")
	if got := masterTunnel(t, flaky).MasterAddr; got != eiPinned {
		t.Fatalf("gate after a roamed report = %q, want %q: the failed write disarmed it", got, eiPinned)
	}
}

// Every manifest edit restarts the controller, and a wire-13 exit's per-peer
// report is not sticky. A pass after the restart whose report carries no peer
// list must find the gate where it was left, and move no port.
func TestAConfirmedGateSurvivesAControllerRestart(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	phase := domain.PerTunnelKeyOff
	s := eiTwoMasters(t, phase, &now)
	ctx := context.Background()
	pinB := pinnedFor("master-xa-2", "203.0.113.2")
	keyB := s.tunnelKeyIn(phase, "master-xa-2")

	recordExit(t, s.st, now, "", domain.MasterPeerStatus{PublicKey: keyB, Endpoint: pinB, LastHandshake: now})
	recordMasters(t, s.st, now)
	if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
		t.Fatalf("gate before the restart = %q, want %q", got, pinB)
	}

	restarted := restartedOver(s.st, s.b, &now)
	now = now.Add(time.Minute)
	recordExit(t, s.st, now, "") // wire 13, the interface could not be read: no peers
	recordMasters(t, s.st, now)
	mustRender(t, restarted, "exit-de-1")
	if got := gateOf(t, restarted, "master-xa-2"); got != pinB {
		t.Errorf("gate after the restart = %q, want it still armed on %q", got, pinB)
	}
	if g, _, _ := s.st.GetAWGPortRotation(ctx, "master-xa-2", "exit-de-1"); g != 0 {
		t.Errorf("port rotated %d time(s) across a restart", g)
	}
}

// The silence clock is part of the confirmation. A tunnel that went quiet before
// the restart rotates AWGRotateAfter after it was confirmed — not AWGRotateAfter
// after whenever the controller last came up.
func TestTheSilenceClockSurvivesAControllerRestart(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	phase := domain.PerTunnelKeyOff
	s := eiTwoMasters(t, phase, &now)
	ctx := context.Background()
	start := now
	pinB := pinnedFor("master-xa-2", "203.0.113.2")
	keyB := s.tunnelKeyIn(phase, "master-xa-2")
	silent := func() {
		recordExit(t, s.st, now, "", domain.MasterPeerStatus{PublicKey: keyB, Endpoint: pinB, LastHandshake: start})
		recordMasters(t, s.st, now)
	}
	gen := func() int {
		g, _, err := s.st.GetAWGPortRotation(ctx, "master-xa-2", "exit-de-1")
		if err != nil {
			t.Fatal(err)
		}
		return g
	}

	silent()
	if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
		t.Fatalf("gate = %q, want %q", got, pinB)
	}

	now = start.Add(AWGRotateAfter - time.Minute)
	restarted := restartedOver(s.st, s.b, &now)
	silent()
	mustRender(t, restarted, "master-xa-2")
	mustRender(t, restarted, "exit-de-1")
	if gen() != 0 {
		t.Fatalf("rotated %d time(s) before the tunnel had been silent for AWGRotateAfter", gen())
	}

	now = start.Add(AWGRotateAfter + time.Minute)
	silent()
	mustRender(t, restarted, "exit-de-1")
	if gen() != 1 {
		t.Errorf("generation = %d, want 1: the restart gave a dead tunnel a fresh silence clock", gen())
	}
}

// A store that fails names what it failed on, so the controller's log says which
// tunnel a render stopped at.
func TestAnUnreadablePortGenerationNamesTheTunnel(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, st, _ := eiFleet(t, &now)
	_, err := restartedOver(rotationReadFails{st}, b, &now).RenderNodeSpec(context.Background(), eiExit)
	if err == nil || !strings.Contains(err.Error(), eiMaster) || !strings.Contains(err.Error(), eiExit) {
		t.Errorf("err = %v, want it to name master %q and exit %q", err, eiMaster, eiExit)
	}
}

// countingConfirmations counts the store traffic of the confirmation table.
type countingConfirmations struct {
	store.Store
	reads, deletes int
}

func (c *countingConfirmations) GetAWGPinConfirmation(ctx context.Context, master, exit string) (string, string, time.Time, error) {
	c.reads++
	return c.Store.GetAWGPinConfirmation(ctx, master, exit)
}

func (c *countingConfirmations) DeleteAWGPinConfirmation(ctx context.Context, master, exit string) error {
	c.deletes++
	return c.Store.DeleteAWGPinConfirmation(ctx, master, exit)
}

// An exit on an old agent is rendered every pass, by itself and by every master.
// Forgetting the pair it does not carry is one delete when there is something to
// forget, and after that no store traffic at all.
func TestForgettingAnUncarriedPairCostsOneWrite(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	phase := domain.PerTunnelKeyOff
	s := eiTwoMasters(t, phase, &now)
	pinB := pinnedFor("master-xa-2", "203.0.113.2")
	recordExit(t, s.st, now, "", domain.MasterPeerStatus{PublicKey: s.tunnelKeyIn(phase, "master-xa-2"), Endpoint: pinB, LastHandshake: now})
	recordMasters(t, s.st, now)
	if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
		t.Fatalf("gate = %q, want %q", got, pinB)
	}

	setWireVersion(t, s.st, "exit-de-1", api.WireAWGExitInitiated)
	counted := &countingConfirmations{Store: s.st}
	b := restartedOver(counted, s.b, &now)
	for i := 0; i < 5; i++ {
		for _, id := range []string{"exit-de-1", "master-xa-1", "master-xa-2"} {
			mustRender(t, b, id)
		}
	}
	if counted.deletes != 1 {
		t.Errorf("deletes = %d over 15 renders, want 1", counted.deletes)
	}
	// One read per pair, ever: the cache answers the rest.
	if counted.reads > 2 {
		t.Errorf("confirmation reads = %d over 15 renders, want at most one per pair", counted.reads)
	}
}

// withExitInitiated is b's fleet with the flag set as given on its first exit —
// the manifest edit, and the controller restart it takes, between two Brokers.
func withExitInitiated(st store.Store, b *Broker, on bool, clock *time.Time) *Broker {
	fleet := b.fleet
	fleet.Exits = append([]config.ExitConfig(nil), b.fleet.Exits...)
	fleet.Exits[0].Transports.AWG.ExitInitiated = on
	return New(st, fleet, slog.New(slog.NewTextHandler(io.Discard, nil)), WithClock(func() time.Time { return *clock }))
}

func generationOf(t *testing.T, st store.Store, master string) int {
	t.Helper()
	g, _, err := st.GetAWGPortRotation(context.Background(), master, "exit-de-1")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// A confirmation exists only while the pinned flow is asked for. With the flag
// off the master dials from an ephemeral port and the exit's endpoint follows it;
// switched on again, a confirmation kept from before would arm the gate at once —
// the master answering only an address the exit is not knocking on yet — and its
// age would move the port of a peer that has simply not handshaken there. The
// gate arms on the exit's report, as it did before anything was stored.
func TestSwitchingTheFlowOffForgetsItsConfirmation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b, st, pub := eiFleet(t, &now)
	ctx := context.Background()
	report(t, st, eiExit, now, now, eiPinned)
	report(t, st, eiMaster, now, now, "")
	if got := masterTunnel(t, b).MasterAddr; got != eiPinned {
		t.Fatalf("gate = %q, want %q", got, eiPinned)
	}

	off := withExitInitiated(st, b, false, &now)
	for _, id := range []string{eiExit, eiMaster} {
		mustRender(t, off, id)
	}
	if addr, _, _, err := st.GetAWGPinConfirmation(ctx, eiMaster, eiExit); err != nil || addr != "" {
		t.Errorf("stored confirmation with the flow switched off = %q, %v; want none", addr, err)
	}

	// On again, long after; the exit's endpoint is wherever the master last dialled from.
	now = now.Add(AWGRotateAfter + AWGRotateMinInterval + 10*time.Minute)
	on := withExitInitiated(st, b, true, &now)
	roamed := eiMasterIP + ":40000"
	report(t, st, eiExit, now, time.Time{}, roamed)
	report(t, st, eiMaster, now, now, "")
	if got := exitPeer(t, on, pub).Endpoint; got != eiPinned {
		t.Errorf("exit endpoint = %q, want the generation-0 port %q: the port was moved on a confirmation from before", got, eiPinned)
	}
	if got := masterTunnel(t, on).MasterAddr; got != "" {
		t.Errorf("gate = %q before the exit reported the pinned endpoint, want it unarmed", got)
	}
	if g := generationOf(t, st, eiMaster); g != 0 {
		t.Errorf("generation = %d, want 0", g)
	}
	report(t, st, eiExit, now, time.Time{}, eiPinned)
	if got := masterTunnel(t, on).MasterAddr; got != eiPinned {
		t.Errorf("gate = %q after the exit reported the pinned endpoint, want %q", got, eiPinned)
	}
}

// The same cycle for a non-base master on an exit that reports per peer.
func TestSwitchingTheFlowOffForgetsANonBaseMastersConfirmation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	phase := domain.PerTunnelKeyOff
	s := eiTwoMasters(t, phase, &now)
	ctx := context.Background()
	pinB := pinnedFor("master-xa-2", "203.0.113.2")
	keyB := s.tunnelKeyIn(phase, "master-xa-2")
	peerB := func(endpoint string, hs time.Time) {
		recordExit(t, s.st, now, "", domain.MasterPeerStatus{PublicKey: keyB, Endpoint: endpoint, LastHandshake: hs})
		recordMasters(t, s.st, now)
	}
	renderAll := func(b *Broker) {
		for _, id := range []string{"exit-de-1", "master-xa-1", "master-xa-2"} {
			mustRender(t, b, id)
		}
	}

	peerB(pinB, now)
	if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
		t.Fatalf("gate = %q, want %q", got, pinB)
	}
	renderAll(withExitInitiated(s.st, s.b, false, &now))
	if addr, _, _, err := s.st.GetAWGPinConfirmation(ctx, "master-xa-2", "exit-de-1"); err != nil || addr != "" {
		t.Errorf("stored confirmation with the flow switched off = %q, %v; want none", addr, err)
	}

	now = now.Add(AWGRotateAfter + AWGRotateMinInterval + 10*time.Minute)
	on := withExitInitiated(s.st, s.b, true, &now)
	peerB("203.0.113.2:40000", time.Time{})
	renderAll(on)
	if got := gateOf(t, on, "master-xa-2"); got != "" {
		t.Errorf("gate = %q before the exit reported the pinned endpoint, want it unarmed", got)
	}
	if g := generationOf(t, s.st, "master-xa-2"); g != 0 {
		t.Errorf("generation = %d, want 0", g)
	}
	peerB(pinB, time.Time{})
	if got := gateOf(t, on, "master-xa-2"); got != pinB {
		t.Errorf("gate = %q after the exit reported the pinned endpoint, want %q", got, pinB)
	}
}

// Most exits never switch the flow on. Having nothing to forget must cost them
// no write, on any render.
func TestAFlowThatWasNeverOnCostsNoWrite(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := eiTwoMasters(t, domain.PerTunnelKeyOff, &now)
	counted := &countingConfirmations{Store: s.st}
	off := withExitInitiated(counted, s.b, false, &now)
	for i := 0; i < 5; i++ {
		for _, id := range []string{"exit-de-1", "master-xa-1", "master-xa-2"} {
			mustRender(t, off, id)
		}
	}
	if counted.deletes != 0 {
		t.Errorf("deletes = %d for a flow that was never on, want 0", counted.deletes)
	}
	if counted.reads > 2 {
		t.Errorf("confirmation reads = %d over 15 renders, want at most one per pair", counted.reads)
	}
}

// The other refusals forget too, wherever they are decided: an agent that went
// back below the wire the flow needs, a master left without an address to knock
// on, a master that lost its peer to a duplicate key.
func TestEveryRefusalForgetsTheConfirmation(t *testing.T) {
	cases := map[string]func(t *testing.T, s seededFleet){
		"the master's agent is too old": func(t *testing.T, s seededFleet) {
			setWireVersion(t, s.st, "master-xa-2", api.WireAWGExitInitiated-1)
		},
		"the master has no public IPv4": func(t *testing.T, s seededFleet) {
			s.b.fleet.Masters = append([]config.MasterConfig(nil), s.b.fleet.Masters...)
			s.b.fleet.Masters[1].PublicIP = "10.9.9.9"
		},
		"the master's key is another master's": func(t *testing.T, s seededFleet) { cloneMasterKeys(t, s) },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1_800_000_000, 0)
			phase := domain.PerTunnelKeyOff
			s := eiTwoMasters(t, phase, &now)
			ctx := context.Background()
			pinB := pinnedFor("master-xa-2", "203.0.113.2")
			recordExit(t, s.st, now, "", domain.MasterPeerStatus{PublicKey: s.tunnelKeyIn(phase, "master-xa-2"), Endpoint: pinB, LastHandshake: now})
			recordMasters(t, s.st, now)
			if got := gateOf(t, s.b, "master-xa-2"); got != pinB {
				t.Fatalf("gate = %q, want %q", got, pinB)
			}
			breakIt(t, s)
			now = now.Add(AWGRotateAfter + AWGRotateMinInterval + 10*time.Minute)
			recordExit(t, s.st, now, "", domain.MasterPeerStatus{PublicKey: s.sharedPubs["master-xa-1"], Endpoint: "203.0.113.9:40000"})
			recordMasters(t, s.st, now)
			for _, id := range []string{"exit-de-1", "master-xa-2"} {
				mustRender(t, s.b, id)
			}
			if addr, _, _, err := s.st.GetAWGPinConfirmation(ctx, "master-xa-2", "exit-de-1"); err != nil || addr != "" {
				t.Errorf("stored confirmation = %q, %v; want none", addr, err)
			}
			if g := generationOf(t, s.st, "master-xa-2"); g != 0 {
				t.Errorf("generation = %d, want 0: a port was moved for a flow that is not rendered", g)
			}
		})
	}
}
