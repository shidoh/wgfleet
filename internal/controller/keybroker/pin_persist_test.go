package keybroker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

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
