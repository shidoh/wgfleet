package camouflage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shidoh/wgfleet/internal/atomicfile"
	"github.com/shidoh/wgfleet/internal/domain"
)

// failuresToClose is how many passes in a row the site must fail before the
// inbounds go back to the fleet-default target: one failed dial is a restart in
// progress, not an outage.
const failuresToClose = 2

// ExpiryWarn is how close to expiry the site's certificate turns the check red.
const ExpiryWarn = 14 * 24 * time.Hour

// internalExpiryWarn replaces ExpiryWarn for Caddy's local CA, whose
// certificates live 12 hours and are renewed at about a third of that.
const internalExpiryWarn = 2 * time.Hour

func expiryWarn(spec domain.CamouflageSpec) time.Duration {
	if spec.ACMECA == domain.CamouflageCAInternal {
		return internalExpiryWarn
	}
	return ExpiryWarn
}

// Gate decides, pass by pass, whether the node's REALITY inbounds use the own
// site as their target (ADR-0039). It opens once the site answers TLS for the
// domain and the domain resolves to the node; it closes after failuresToClose
// failed TLS checks in a row. A wrong DNS answer alone never closes it: the
// local target keeps working for every peer, and moving away from it would
// strand the peers that already send the domain.
//
// The agent owns one Gate for its lifetime; the decision is also persisted, so
// a restarted agent reports what its inbounds actually serve from its first pass.
type Gate struct {
	mu        sync.Mutex
	statePath string // "" ⇒ not persisted (tests)
	readOnly  bool   // loaded from statePath but never written (dry runs)
	dirty     bool   // the last persist failed; retried on the next Observe
	active    string // the domain served as target; "" ⇒ the fleet default
	failures  int
	last      Result
	checked   bool
}

// NewGate loads the persisted decision from statePath ("" keeps it in memory).
func NewGate(statePath string) *Gate {
	g := &Gate{statePath: statePath}
	if statePath != "" {
		if b, err := os.ReadFile(statePath); err == nil {
			g.active = strings.TrimSpace(string(b))
		}
	}
	return g
}

// NewReadOnlyGate loads the persisted decision like NewGate but never writes
// it: a dry run starts from what the node actually serves and must not change
// what the next real pass reports.
func NewReadOnlyGate(statePath string) *Gate {
	g := NewGate(statePath)
	g.readOnly = true
	return g
}

// Observe feeds one probe result for spec and returns whether the decision
// changed. spec nil (no camouflage) closes the gate.
func (g *Gate) Observe(spec *domain.CamouflageSpec, r Result) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	prev := g.active
	switch {
	case spec == nil:
		g.active, g.failures, g.last, g.checked = "", 0, Result{}, false
	default:
		g.last, g.checked = r, true
		if r.TLSOK {
			g.failures = 0
		} else {
			g.failures++
		}
		switch {
		case g.active != spec.Domain && r.OK():
			g.active = spec.Domain
		case g.active != "" && g.active != spec.Domain:
			g.active = "" // the domain changed; the new one has to earn it
		case g.active != "" && g.failures >= failuresToClose:
			g.active = ""
		}
	}
	changed := g.active != prev
	if !changed && !g.dirty {
		return false, nil
	}
	err := g.persist()
	g.dirty = err != nil
	return changed, err
}

func (g *Gate) persist() error {
	if g.statePath == "" || g.readOnly {
		return nil
	}
	if g.active == "" {
		if err := os.Remove(g.statePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear camouflage state: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(g.statePath), 0o755); err != nil {
		return fmt.Errorf("camouflage state dir: %w", err)
	}
	if err := atomicfile.Write(g.statePath, []byte(g.active+"\n"), 0o644); err != nil {
		return fmt.Errorf("persist camouflage state: %w", err)
	}
	return nil
}

// ActiveDomain is the domain the inbounds use as target right now; "" ⇒ the
// fleet default. It is what the node reports to the controller.
func (g *Gate) ActiveDomain() string {
	if g == nil {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active
}

// Last is the most recent probe result and whether there was one.
func (g *Gate) Last() (Result, bool) {
	if g == nil {
		return Result{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last, g.checked
}

// Check is the node's `camouflage` health check for spec; ok=false with a
// reason while the site is not the target, cannot be checked, or its
// certificate expires within ExpiryWarn.
func (g *Gate) Check(spec domain.CamouflageSpec, now time.Time) domain.HealthCheck {
	hc := domain.HealthCheck{Name: "camouflage"}
	r, checked := g.Last()
	active := g.ActiveDomain() == spec.Domain
	left := r.NotAfter.Sub(now)
	switch {
	case !checked:
		hc.Detail = "site not checked yet"
	case !r.TLSOK:
		hc.Detail = "site down: " + r.Reason
		if active {
			hc.Detail += " (still the target until it fails again)"
		}
	case !r.DNSOK:
		hc.Detail = r.Reason
	case !active:
		hc.Detail = "site ready; switching the target on the next pass"
	case !r.NotAfter.IsZero() && left < expiryWarn(spec):
		hc.Detail = fmt.Sprintf("certificate for %s expires in %s", spec.Domain, left.Round(time.Hour))
	default:
		hc.OK = true
		hc.Detail = fmt.Sprintf("serving %s, certificate valid %d more days", spec.Domain, int(left.Hours()/24))
	}
	return hc
}

// Target is the xray renderer's switch for spec: the domain the inbounds accept
// and the local target while the gate is open ("" while it is closed). Both are
// empty when the node has no camouflage.
func (g *Gate) Target(spec *domain.CamouflageSpec) (domainName, target string) {
	if spec == nil {
		return "", ""
	}
	if g.ActiveDomain() == spec.Domain {
		return spec.Domain, spec.LocalTarget()
	}
	return spec.Domain, ""
}

// Evaluate probes the site with p and feeds the result to the gate.
func (g *Gate) Evaluate(ctx context.Context, spec *domain.CamouflageSpec, p Prober) (bool, error) {
	if spec == nil {
		return g.Observe(nil, Result{})
	}
	return g.Observe(spec, p.Probe(ctx, *spec))
}
