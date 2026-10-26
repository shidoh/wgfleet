// Package uplink measures a master's own uplink by opening TCP connections to
// the other masters and closing them, never sending data.
//
// A filter that delays or drops a share of a host's handshakes (live 2026-10-16:
// one master, ~15% of outbound SYNs answered only after the kernel's 1 s
// retransmit) leaves ping clean and every tunnel up, so nothing else notices. A
// connect slower than SlowAfter is that retransmit; the same pair measured from
// the other end says whose uplink it is.
package uplink

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// Probe results, the values of the metric's result label.
const (
	ResultOK   = "ok"
	ResultSlow = "slow"
	ResultFail = "fail"
	// ResultRefused is a reset in answer to the SYN: the path delivered it and
	// something answered. A peer restarting its listener does this, and so does
	// a filter that injects resets — kept apart from fail (no answer at all) so
	// the two can be told apart.
	ResultRefused = "refused"
)

const (
	// SlowAfter is the connect time that only a retransmitted SYN reaches: the
	// kernel's initial SYN RTO is 1 s and no path between two masters is near it.
	SlowAfter = 900 * time.Millisecond
	// DialTimeout lets the kernel's second SYN retransmit (sent at 3 s) be
	// answered, so a connect that needed it reads as slow, not failed; the third
	// would go out at 7 s. Measured on the stand with 20% SYN-ACK loss: a 3 s
	// timeout filed those connects as failures.
	DialTimeout = 4 * time.Second
	// Interval is how often every target is measured: 2880 samples a day per
	// peer, enough for a daily share to move by a fraction of a percent.
	Interval = 30 * time.Second
)

// Recorder receives one observation per probe. d is the connect time; it is the
// timeout for a failure.
type Recorder interface {
	ObserveUplinkProbe(peer, result string, d time.Duration)
}

// Prober measures the targets it was last given, every Interval, until its
// context ends. Safe to feed new targets from another goroutine.
type Prober struct {
	rec      Recorder
	targets  atomic.Pointer[[]domain.UplinkProbeTarget]
	dial     func(ctx context.Context, addr netip.AddrPort) error
	now      func() time.Time
	interval time.Duration
}

// New returns a prober with no targets; it measures nothing until SetTargets.
func New(rec Recorder) *Prober {
	return &Prober{rec: rec, dial: dialTCP, now: time.Now, interval: Interval}
}

// SetTargets replaces the targets. The prober keeps its own copy.
func (p *Prober) SetTargets(ts []domain.UplinkProbeTarget) {
	cp := append([]domain.UplinkProbeTarget(nil), ts...)
	p.targets.Store(&cp)
}

// Run measures every Interval until ctx ends.
func (p *Prober) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.ProbeOnce(ctx)
		}
	}
}

// ProbeOnce measures every target once, in parallel, so one black-holed peer
// does not delay or skew the measurement of another.
func (p *Prober) ProbeOnce(ctx context.Context) {
	ts := p.targets.Load()
	if ts == nil {
		return
	}
	var wg sync.WaitGroup
	for _, tg := range *ts {
		wg.Add(1)
		go func(tg domain.UplinkProbeTarget) {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, DialTimeout)
			defer cancel()
			start := p.now()
			err := p.dial(dctx, tg.Addr)
			d := p.now().Sub(start)
			if ctx.Err() != nil {
				// The agent is stopping: a dial it cut short says nothing about the uplink.
				return
			}
			p.rec.ObserveUplinkProbe(tg.Name, classify(d, err), d)
		}(tg)
	}
	wg.Wait()
}

func classify(d time.Duration, err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return ResultRefused
	case err != nil:
		return ResultFail
	case d >= SlowAfter:
		return ResultSlow
	}
	return ResultOK
}

// dialTCP completes a TCP handshake and closes the connection at once.
func dialTCP(ctx context.Context, addr netip.AddrPort) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return err
	}
	return c.Close()
}
