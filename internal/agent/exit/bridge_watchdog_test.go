package exit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// fakeSS serves `ss -tniH state established` from a mutable table and records
// every `ss -K` it is asked to run.
type fakeSS struct {
	socks map[string]uint64 // "local peer" → bytes_received
	kills []string
}

func (f *fakeSS) run(_ context.Context, name string, args ...string) (string, error) {
	if name != "ss" {
		return "", fmt.Errorf("unexpected %s", name)
	}
	if len(args) > 0 && args[0] == "-K" {
		f.kills = append(f.kills, strings.Join(args, " "))
		return "", nil
	}
	var b strings.Builder
	for k, n := range f.socks {
		lp := strings.Fields(k)
		fmt.Fprintf(&b, "0 0 %s %s\n\t cubic bytes_received:%d\n", lp[0], lp[1], n)
	}
	return b.String(), nil
}

type watchdogRig struct {
	w   *BridgeWatchdog
	ss  *fakeSS
	now time.Time
}

func newWatchdogRig() *watchdogRig {
	r := &watchdogRig{ss: &fakeSS{socks: map[string]uint64{}}, now: time.Unix(1_700_000_000, 0)}
	bridge := &domain.RealityBridgeSpec{Portals: []domain.RealityPortalPeer{
		{Master: "m1", Address: "203.0.113.1:48123"},
		{Master: "m2", Address: "203.0.113.2:41000"},
	}}
	r.w = NewBridgeWatchdog(slog.New(slog.NewTextHandler(io.Discard, nil)), func() *domain.RealityBridgeSpec { return bridge })
	r.w.run = r.ss.run
	r.w.now = func() time.Time { return r.now }
	return r
}

func (r *watchdogRig) tickAfter(d time.Duration) {
	r.now = r.now.Add(d)
	r.w.Tick(context.Background())
}

// The portal's mux keepalive arrives every ~10 s: a socket whose byte count
// grows is alive, whatever else is going on.
func TestBridgeWatchdogLeavesAGrowingSocketAlone(t *testing.T) {
	r := newWatchdogRig()
	r.ss.socks["198.51.100.7:41182 203.0.113.1:48123"] = 100
	r.tickAfter(0)
	for i := range 10 {
		r.ss.socks["198.51.100.7:41182 203.0.113.1:48123"] = uint64(200 + i)
		r.tickAfter(10 * time.Second)
	}
	if len(r.ss.kills) != 0 {
		t.Fatalf("killed a live socket: %v", r.ss.kills)
	}
}

// A flow frozen one way receives nothing while it still looks established —
// measured: nothing else notices it for ~100 s. 30 s without a byte kills
// exactly that socket and nothing else.
func TestBridgeWatchdogKillsAStalledSocketOnly(t *testing.T) {
	r := newWatchdogRig()
	r.ss.socks["198.51.100.7:41182 203.0.113.1:48123"] = 500 // will stall
	r.ss.socks["198.51.100.7:41190 203.0.113.2:41000"] = 500 // keeps growing
	r.ss.socks["198.51.100.7:22 192.0.2.50:51234"] = 1       // not a bridge socket
	r.tickAfter(0)
	for i := 1; i <= 2; i++ {
		r.ss.socks["198.51.100.7:41190 203.0.113.2:41000"] = uint64(500 + i)
		r.tickAfter(10 * time.Second)
	}
	if len(r.ss.kills) != 0 {
		t.Fatalf("killed before 30 s: %v", r.ss.kills)
	}
	r.ss.socks["198.51.100.7:41190 203.0.113.2:41000"] = 600
	r.tickAfter(10 * time.Second)
	if len(r.ss.kills) != 1 || r.ss.kills[0] != "-K dst 203.0.113.1 dport = 48123 sport = :41182" {
		t.Fatalf("kills = %v, want exactly the stalled socket", r.ss.kills)
	}
	if got := r.w.Kills()["m1"]; got != 1 {
		t.Errorf("kills for m1 = %d, want 1", got)
	}
	if got := r.w.Kills()["m2"]; got != 0 {
		t.Errorf("kills for m2 = %d, want 0", got)
	}
	// Killed once; the next tick does not kill it again while ss still lists it.
	r.tickAfter(5 * time.Second)
	if len(r.ss.kills) != 1 {
		t.Errorf("killed the same socket twice: %v", r.ss.kills)
	}
}

// A socket that is gone is forgotten: the redialled flow with the same local
// port later starts its own clock.
func TestBridgeWatchdogForgetsVanishedSockets(t *testing.T) {
	r := newWatchdogRig()
	key := "198.51.100.7:41182 203.0.113.1:48123"
	r.ss.socks[key] = 500
	r.tickAfter(0)
	delete(r.ss.socks, key)
	r.tickAfter(20 * time.Second)
	r.ss.socks[key] = 500
	r.tickAfter(20 * time.Second)
	if len(r.ss.kills) != 0 {
		t.Fatalf("a socket that reappeared inherited the old clock: %v", r.ss.kills)
	}
}

// Without a bridge there is nothing to watch, and ss is not run.
func TestBridgeWatchdogIdleWithoutABridge(t *testing.T) {
	r := newWatchdogRig()
	r.w.bridge = func() *domain.RealityBridgeSpec { return nil }
	r.ss.socks["198.51.100.7:41182 203.0.113.1:48123"] = 1
	r.tickAfter(0)
	r.tickAfter(time.Minute)
	if len(r.ss.kills) != 0 {
		t.Fatalf("kills without a bridge: %v", r.ss.kills)
	}
}
