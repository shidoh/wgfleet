// Package egress implements the exit agent's censorship-adaptive egress failover
// (ADR-0017): it selects the active egress method within the controller-provided
// priority chain, demoting on a confirmed block (ADR-0016) and promoting back to
// the preferred method after sustained recovery. Selection is a local decision in
// the bounds of the declarative chain — it keeps working when the controller/mgmt
// overlay is unreachable, which is exactly when censorship hits.
package egress

import (
	"context"

	"github.com/shidoh/wgfleet/internal/domain"
)

// DefaultRecoverPasses is the number of consecutive recovery-probe successes
// required to promote a failed-over node back to its preferred egress. Promotion
// is deliberately slower than demotion so a flapping path does not bounce client
// traffic.
const DefaultRecoverPasses = 2

// WARPInterface is the wgcf interface name the routing planner points client
// traffic at when WARP is the active egress. It must match the interface the exit
// WARP planner brings up (derived from the wgcf.conf basename).
const WARPInterface = "wgcf"

// RecoverProbe reports whether the preferred egress is reachable again. It is
// called only while the node is on a fallback, and (per ADR-0017) probes the
// still-up wgcf interface so recovery is detected without disrupting client
// traffic.
type RecoverProbe func(ctx context.Context) bool

// Selector tracks the active egress across reconcile passes. Hold one per agent;
// its state is in-memory, so a restart resets to the preferred method — correct,
// since the preferred transport should be re-tried first.
type Selector struct {
	// RecoverPasses overrides DefaultRecoverPasses when > 0 (tests use a small value).
	RecoverPasses int
	active        domain.EgressMethod
	recovers      int
}

// Active returns the egress the agent should converge to this pass, defaulting to
// the chain's preferred method before the first Step.
func (s *Selector) Active(chain []domain.EgressMethod) domain.EgressMethod {
	if s.active == "" && len(chain) > 0 {
		s.active = chain[0]
	}
	return s.active
}

// Step advances the selector after a pass and returns the active egress to
// converge to next. class is the egress classification of the ACTIVE egress
// (ADR-0016): it is only meaningful (non-empty) while the active egress is WARP.
// recover is used only on a fallback to probe the preferred egress.
func (s *Selector) Step(ctx context.Context, chain []domain.EgressMethod, class domain.EgressReachability, recover RecoverProbe) domain.EgressMethod {
	if len(chain) == 0 {
		return s.active
	}
	preferred := chain[0]
	if s.active == "" {
		s.active = preferred
	}

	if s.active == preferred {
		// On the preferred egress: demote on a confirmed block if a fallback exists.
		if class == domain.EgressReachBlocked {
			if next, ok := nextAfter(chain, s.active); ok {
				s.active = next
				s.recovers = 0
			}
		}
		return s.active
	}

	// On a fallback: probe the preferred egress; promote after sustained recovery.
	threshold := s.RecoverPasses
	if threshold <= 0 {
		threshold = DefaultRecoverPasses
	}
	if recover != nil && recover(ctx) {
		s.recovers++
		if s.recovers >= threshold {
			s.active = preferred
			s.recovers = 0
		}
	} else {
		s.recovers = 0
	}
	return s.active
}

// EffectiveSpec returns spec adjusted so the data plane converges to the active
// egress: Egress set to active, and routing pointing client traffic at wgcf only
// when active is WARP (empty otherwise — direct egress runs no policy routing). The
// EgressChain is preserved, so the WARP planner keeps wgcf up while WARP remains a
// candidate. A no-op when active already matches the preferred egress in spec.
func EffectiveSpec(spec domain.NodeSpec, active domain.EgressMethod) domain.NodeSpec {
	if active == "" || active == spec.Egress {
		return spec
	}
	eff := spec
	eff.Egress = active
	if active == domain.EgressWARP {
		eff.Routing.EgressInterface = WARPInterface
	} else {
		eff.Routing.EgressInterface = ""
	}
	return eff
}

func nextAfter(chain []domain.EgressMethod, m domain.EgressMethod) (domain.EgressMethod, bool) {
	for i, c := range chain {
		if c == m && i+1 < len(chain) {
			return chain[i+1], true
		}
	}
	return "", false
}
