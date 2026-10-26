package uplink

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

type observation struct {
	peer, result string
	d            time.Duration
}

type recorder struct {
	mu  sync.Mutex
	got []observation
}

func (r *recorder) ObserveUplinkProbe(peer, result string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, observation{peer, result, d})
}

func (r *recorder) sorted() []observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]observation(nil), r.got...)
	sort.Slice(out, func(i, j int) bool { return out[i].peer < out[j].peer })
	return out
}

func target(name, addr string) domain.UplinkProbeTarget {
	return domain.UplinkProbeTarget{Name: name, Addr: netip.MustParseAddrPort(addr)}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
		err  error
		want string
	}{
		{"fast connect", 45 * time.Millisecond, nil, ResultOK},
		{"just under the SYN retransmit", SlowAfter - time.Millisecond, nil, ResultOK},
		{"a retransmitted SYN", SlowAfter, nil, ResultSlow},
		{"two retransmits", 2100 * time.Millisecond, nil, ResultSlow},
		{"timeout", DialTimeout, context.DeadlineExceeded, ResultFail},
		{"refused fast is still a failure", 2 * time.Millisecond, errors.New("connection refused"), ResultFail},
	}
	for _, c := range cases {
		if got := classify(c.d, c.err); got != c.want {
			t.Errorf("%s: classify(%v, %v) = %q, want %q", c.name, c.d, c.err, got, c.want)
		}
	}
}

func TestProbeOnceMeasuresEveryTarget(t *testing.T) {
	rec := &recorder{}
	p := New(rec)
	p.dial = func(_ context.Context, addr netip.AddrPort) error {
		if addr.Port() == 2 {
			return errors.New("refused")
		}
		return nil
	}
	// A stopped clock: every connect takes zero time, so only the error decides.
	p.now = func() time.Time { return time.Unix(0, 0) }
	p.SetTargets([]domain.UplinkProbeTarget{target("a", "203.0.113.1:1"), target("b", "203.0.113.2:2")})

	p.ProbeOnce(context.Background())

	got := rec.sorted()
	if len(got) != 2 || got[0].peer != "a" || got[0].result != ResultOK || got[1].peer != "b" || got[1].result != ResultFail {
		t.Fatalf("observations = %+v, want a=ok b=fail", got)
	}
}

// The probe's time is the dial's own time, and a dial is bounded: a black hole
// must come back as a failure within DialTimeout, not hang the prober.
func TestDialIsBoundedByDialTimeout(t *testing.T) {
	rec := &recorder{}
	p := New(rec)
	var deadline time.Time
	p.dial = func(ctx context.Context, _ netip.AddrPort) error {
		deadline, _ = ctx.Deadline()
		<-ctx.Done()
		return ctx.Err()
	}
	p.SetTargets([]domain.UplinkProbeTarget{target("hole", "203.0.113.9:443")})
	start := time.Now()
	p.ProbeOnce(context.Background())
	if took := time.Since(start); took > DialTimeout+time.Second {
		t.Fatalf("a black-holed target held the probe %v", took)
	}
	if deadline.IsZero() || deadline.Sub(start) > DialTimeout+100*time.Millisecond {
		t.Fatalf("dial deadline %v after start, want at most %v", deadline.Sub(start), DialTimeout)
	}
	if got := rec.sorted(); len(got) != 1 || got[0].result != ResultFail {
		t.Fatalf("observations = %+v, want one failure", got)
	}
}

func TestNoTargetsMeasuresNothing(t *testing.T) {
	rec := &recorder{}
	p := New(rec)
	p.dial = func(context.Context, netip.AddrPort) error {
		t.Fatal("dialled with no targets")
		return nil
	}
	p.ProbeOnce(context.Background())
	p.SetTargets(nil)
	p.ProbeOnce(context.Background())
	if got := rec.sorted(); len(got) != 0 {
		t.Fatalf("observations = %+v, want none", got)
	}
}

// SetTargets keeps its own copy: the agent hands it a slice from a spec it goes
// on to reuse, and the prober reads it from another goroutine.
func TestSetTargetsCopies(t *testing.T) {
	p := New(&recorder{})
	ts := []domain.UplinkProbeTarget{target("a", "203.0.113.1:443")}
	p.SetTargets(ts)
	ts[0].Name = "changed"
	if got := *p.targets.Load(); got[0].Name != "a" {
		t.Fatalf("stored target renamed to %q through the caller's slice", got[0].Name)
	}
}

// The real dialer against a real listener: a local accept is ok, a closed port is
// a failure. Proves the default dialer connects and closes, not just that the
// fakes agree with each other.
func TestDefaultDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	open := netip.MustParseAddrPort(ln.Addr().String())
	if err := dialTCP(context.Background(), open); err != nil {
		t.Fatalf("dial to a listener: %v", err)
	}
	_ = ln.Close()
	if err := dialTCP(context.Background(), open); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
}

func TestRunStopsWithItsContext(t *testing.T) {
	p := New(&recorder{})
	p.interval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
