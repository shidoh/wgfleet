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

// fakeSS serves `ss -tniH state established` like the kernel does: lastrcv is
// the milliseconds since the socket last received data (or since it was set
// up, if it never has). It records every `ss -K` it is asked to run.
type fakeSS struct {
	now   func() time.Time
	socks map[string]time.Time // "local peer" → last receive
	noRcv bool                 // print no lastrcv at all
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
	for k, last := range f.socks {
		lp := strings.Fields(k)
		fmt.Fprintf(&b, "0 0 %s %s\n\t cubic rto:204", lp[0], lp[1])
		if !f.noRcv {
			fmt.Fprintf(&b, " lastsnd:120 lastrcv:%d lastack:40", f.now().Sub(last).Milliseconds())
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

type watchdogRig struct {
	w   *BridgeWatchdog
	ss  *fakeSS
	now time.Time
}

func newWatchdogRig() *watchdogRig {
	r := &watchdogRig{now: time.Unix(1_700_000_000, 0)}
	r.ss = &fakeSS{now: func() time.Time { return r.now }, socks: map[string]time.Time{}}
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

const (
	frozen = "198.51.100.7:41182 203.0.113.1:48123"
	live   = "198.51.100.7:41190 203.0.113.2:41000"
)

// The portal's mux keepalive arrives every ~10 s: a socket that keeps receiving
// is alive, whatever else is going on.
func TestBridgeWatchdogLeavesAReceivingSocketAlone(t *testing.T) {
	r := newWatchdogRig()
	r.ss.socks[live] = r.now
	for range 12 {
		r.tickAfter(10 * time.Second)
		r.ss.socks[live] = r.now
	}
	if len(r.ss.kills) != 0 {
		t.Fatalf("killed a live socket: %v", r.ss.kills)
	}
}

// A flow frozen one way receives nothing while it still looks established —
// measured: nothing else notices it for ~100 s. 30 s without a byte kills
// exactly that socket and nothing else, including one that never received a
// byte at all (frozen from its first segment, seen on the stand).
func TestBridgeWatchdogKillsAStalledSocketOnly(t *testing.T) {
	r := newWatchdogRig()
	r.ss.socks[frozen] = r.now
	r.ss.socks[live] = r.now
	r.ss.socks["198.51.100.7:22 192.0.2.50:51234"] = r.now.Add(-time.Hour) // not a bridge socket
	for range 5 {
		r.tickAfter(5 * time.Second)
		r.ss.socks[live] = r.now
	}
	if len(r.ss.kills) != 0 {
		t.Fatalf("killed before 30 s: %v", r.ss.kills)
	}
	r.tickAfter(5 * time.Second)
	if len(r.ss.kills) != 1 || r.ss.kills[0] != "-K dst 203.0.113.1 dport = :48123 sport = :41182" {
		t.Fatalf("kills = %v, want exactly the stalled socket", r.ss.kills)
	}
	if got := r.w.Kills(); got["m1"] != 1 || got["m2"] != 0 {
		t.Errorf("kills = %v, want m1:1", got)
	}
	// Not again on the next tick while ss still lists it.
	r.tickAfter(5 * time.Second)
	if len(r.ss.kills) != 1 {
		t.Errorf("killed the same socket twice in a row: %v", r.ss.kills)
	}
}

// A kill that did not take effect — the socket still listed and still silent —
// is retried after another stall interval rather than forgotten.
func TestBridgeWatchdogRetriesAKillThatDidNotTakeEffect(t *testing.T) {
	r := newWatchdogRig()
	r.ss.socks[frozen] = r.now
	r.tickAfter(30 * time.Second)
	if len(r.ss.kills) != 1 {
		t.Fatalf("first kill: %v", r.ss.kills)
	}
	r.tickAfter(30 * time.Second)
	if len(r.ss.kills) != 2 {
		t.Fatalf("a socket that survived its kill was not retried: %v", r.ss.kills)
	}
}

// An ss that prints no lastrcv gives the watchdog nothing to judge.
func TestBridgeWatchdogDoesNotJudgeWithoutLastrcv(t *testing.T) {
	r := newWatchdogRig()
	r.ss.noRcv = true
	r.ss.socks[frozen] = r.now.Add(-time.Hour)
	r.tickAfter(time.Minute)
	r.tickAfter(time.Minute)
	if len(r.ss.kills) != 0 {
		t.Fatalf("killed without lastrcv: %v", r.ss.kills)
	}
}

// Without a bridge there is nothing to watch.
func TestBridgeWatchdogIdleWithoutABridge(t *testing.T) {
	r := newWatchdogRig()
	r.w.bridge = func() *domain.RealityBridgeSpec { return nil }
	r.ss.socks[frozen] = r.now.Add(-time.Hour)
	r.tickAfter(time.Minute)
	if len(r.ss.kills) != 0 {
		t.Fatalf("kills without a bridge: %v", r.ss.kills)
	}
}
