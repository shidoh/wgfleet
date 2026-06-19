package health

import (
	"context"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// constProbe returns a fixed rate (and no error) every call.
func constProbe(rate float64) ThroughputProbe {
	return func(context.Context) (float64, error) { return rate, nil }
}

func TestThroughputWatchdogHysteresis(t *testing.T) {
	w := &ThroughputWatchdog{MinBytesPerSec: 256000, DegradeAfter: 3, RecoverAfter: 2}
	ctx := context.Background()
	slow := constProbe(25 * 1024)   // 25 KB/s — well below the 250 KB/s floor
	fast := constProbe(5000 * 1024) // 5 MB/s — well above

	// Idle link (passive 0), below floor but under the streak: NOT yet degraded.
	for i := 1; i < 3; i++ {
		deg, chk := w.Observe(ctx, 0, slow)
		if deg || !chk.OK {
			t.Fatalf("probe %d: degraded too early (deg=%v ok=%v)", i, deg, chk.OK)
		}
	}
	// Third consecutive below-floor probe trips degraded.
	deg, chk := w.Observe(ctx, 0, slow)
	if !deg || chk.OK || chk.Name != domain.CheckEgressThroughput {
		t.Fatalf("expected degraded after 3 slow probes, got deg=%v chk=%+v", deg, chk)
	}

	// One fast probe is not enough to recover (RecoverAfter=2).
	if deg, _ := w.Observe(ctx, 0, fast); !deg {
		t.Fatal("recovered after a single fast probe (should need 2)")
	}
	// Second consecutive fast probe recovers.
	if deg, chk := w.Observe(ctx, 0, fast); deg || !chk.OK {
		t.Fatalf("expected recovery after 2 fast probes, got deg=%v ok=%v", deg, chk.OK)
	}
}

func TestThroughputWatchdogStaysHealthyAboveFloor(t *testing.T) {
	w := &ThroughputWatchdog{MinBytesPerSec: 256000}
	for i := 0; i < 5; i++ {
		if deg, chk := w.Observe(context.Background(), 0, constProbe(1024*1024)); deg || !chk.OK {
			t.Fatalf("healthy throughput must never degrade, got deg=%v ok=%v", deg, chk.OK)
		}
	}
}

func TestThroughputWatchdogProbeErrorCountsAsBad(t *testing.T) {
	w := &ThroughputWatchdog{MinBytesPerSec: 256000, DegradeAfter: 2}
	errProbe := ThroughputProbe(func(context.Context) (float64, error) {
		return 0, context.DeadlineExceeded
	})
	w.Observe(context.Background(), 0, errProbe)
	deg, chk := w.Observe(context.Background(), 0, errProbe)
	if !deg || chk.OK {
		t.Fatalf("probe errors must count toward degradation, got deg=%v ok=%v", deg, chk.OK)
	}
}

func TestThroughputWatchdogPassiveRescuesBusyLink(t *testing.T) {
	// A link saturated by real client traffic (passive 5 MB/s) is healthy WITHOUT
	// running the active probe — the operator's false-positive scenario: a busy exit
	// must not be auto-suspended just because a competing probe would read low.
	w := &ThroughputWatchdog{MinBytesPerSec: 256000}
	neverProbe := ThroughputProbe(func(context.Context) (float64, error) {
		t.Fatal("active probe must not run when live traffic already meets the floor")
		return 0, nil
	})
	for i := 0; i < 5; i++ {
		if deg, chk := w.Observe(context.Background(), 5000*1024, neverProbe); deg || !chk.OK {
			t.Fatalf("busy link must read healthy via live traffic, got deg=%v ok=%v", deg, chk.OK)
		}
	}
}

func TestThroughputWatchdogIdleHealthyViaProbe(t *testing.T) {
	// Idle link (no real traffic) but a fast probe ⇒ healthy: the probe is uncontended
	// and accurately reflects the path's capacity.
	w := &ThroughputWatchdog{MinBytesPerSec: 256000, DegradeAfter: 2}
	for i := 0; i < 4; i++ {
		if deg, _ := w.Observe(context.Background(), 0, constProbe(5000*1024)); deg {
			t.Fatal("idle link with a fast probe must stay healthy")
		}
	}
}

func TestParseThroughput(t *testing.T) {
	cases := map[string]struct {
		out  string
		rate float64
		ok   bool
	}{
		"healthy":     {"262144 0.1", 2621440, true},
		"throttled":   {"204800 8.0", 25600, true},
		"zero time":   {"262144 0", 0, false},
		"empty":       {"", 0, false},
		"one field":   {"262144", 0, false},
		"non-numeric": {"abc def", 0, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rate, ok := parseThroughput(c.out)
			if ok != c.ok || (ok && rate != c.rate) {
				t.Errorf("parseThroughput(%q) = %v,%v want %v,%v", c.out, rate, ok, c.rate, c.ok)
			}
		})
	}
}
