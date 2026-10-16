package master

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/agent/sockwatch"
	"github.com/shidoh/wgfleet/internal/domain"
)

type portalSock struct{ lastsnd, lastack time.Duration }

func portalWatchRig(t *testing.T, socks map[string]portalSock) (*sockwatch.Watchdog, *[]string) {
	t.Helper()
	var kills []string
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		if args[0] == "-K" {
			kills = append(kills, strings.Join(args, " "))
			return "", nil
		}
		var b strings.Builder
		for k, s := range socks {
			lp := strings.Fields(k)
			fmt.Fprintf(&b, "0 0 %s %s\n\t cubic lastsnd:%d lastrcv:99999 lastack:%d\n", lp[0], lp[1], s.lastsnd.Milliseconds(), s.lastack.Milliseconds())
		}
		return b.String(), nil
	}
	portal := &domain.RealityPortalSpec{ListenPort: 56205}
	names := map[string]string{"192.0.2.5": "exit-a"}
	w := NewPortalWatchdog(slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() *domain.RealityPortalSpec { return portal },
		func(ip string) string { return names[ip] },
		sockwatch.WithRunner(run))
	return w, &kills
}

// The portal sends a mux keepalive every ~10 s, so a live bridge ACKs within an
// RTT. A portal socket whose data has gone unacknowledged for 30 s belongs to a
// bridge that is gone: measured on the stand after a 60 s ban, such a socket
// stayed ESTABLISHED for minutes (1416 retransmissions) and xray kept sending
// streams into it. An idle socket that sent nothing is left alone.
func TestPortalWatchdogKillsOnlyUnacknowledgedPortalSockets(t *testing.T) {
	w, kills := portalWatchRig(t, map[string]portalSock{
		"203.0.113.1:56205 192.0.2.5:36328": {lastsnd: 120 * time.Second, lastack: 278 * time.Second}, // zombie
		"203.0.113.1:56205 192.0.2.5:55332": {lastsnd: 5 * time.Second, lastack: 5 * time.Second},     // live
		"203.0.113.1:56205 192.0.2.6:40000": {lastsnd: 90 * time.Second, lastack: 60 * time.Second},   // idle, nothing outstanding
		"203.0.113.1:22 192.0.2.5:51234":    {lastsnd: 1 * time.Second, lastack: 500 * time.Second},   // not the portal
		"10.0.0.1:41000 192.0.2.5:56205":    {lastsnd: 1 * time.Second, lastack: 500 * time.Second},   // portal port as the PEER
	})
	w.Tick(context.Background())
	if len(*kills) != 1 || (*kills)[0] != "-K dst 192.0.2.5 dport = :36328 sport = :56205" {
		t.Fatalf("kills = %v, want the zombie only", *kills)
	}
	if got := w.Kills()["exit-a"]; got != 1 {
		t.Errorf("kills by exit = %v", w.Kills())
	}
}

func TestPortalWatchdogIdleWithoutAPortal(t *testing.T) {
	var ran bool
	w := NewPortalWatchdog(slog.New(slog.NewTextHandler(io.Discard, nil)),
		func() *domain.RealityPortalSpec { return nil }, func(string) string { return "" },
		sockwatch.WithRunner(func(context.Context, string, ...string) (string, error) { ran = true; return "", nil }))
	w.Tick(context.Background())
	if ran {
		t.Error("ss run without a portal")
	}
}
