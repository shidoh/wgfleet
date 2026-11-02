package health

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/domain"
)

// EgressBlockThreshold is the number of consecutive warp-egress failures before
// the classifier runs the active confirmation and may escalate to "blocked". A
// single failed probe is treated as a transient blip ("degraded"); only a
// persistent failure whose path confirmation also fails is a censorship block.
const EgressBlockThreshold = 3

// EgressClassifier turns each pass's warp-egress check result into an
// EgressReachability classification, tracking consecutive failures so a transient
// Cloudflare blip reads as "degraded" and only a persistent failure whose active
// path confirmation also fails reads as "blocked" (ISP/DPI). It is
// detect-only: it produces a signal (a self-check + classification), it does not
// switch transport. Hold one instance per agent; Classify mutates the streak.
type EgressClassifier struct {
	// Threshold overrides EgressBlockThreshold when > 0 (tests use a small value).
	Threshold int
	fails     int
}

// Classify inspects the already-run checks for the warp-egress result and returns
// the egress classification plus the self-check to append (named
// CheckEgressReachability), or ("", nil) when egress is not WARP (no warp-egress
// check present — nothing to classify). confirm is the active path-reachability
// probe; it is called only once the failure streak crosses the threshold, so the
// common healthy path runs nothing extra.
func (e *EgressClassifier) Classify(ctx context.Context, checks []domain.HealthCheck, confirm Probe) (domain.EgressReachability, *domain.HealthCheck) {
	egress, found := findCheck(checks, "warp-egress")
	if !found {
		e.fails = 0
		return "", nil
	}
	if egress.OK {
		e.fails = 0
		return domain.EgressReachOK, reachCheck(domain.EgressReachOK, "egress via WARP confirmed")
	}

	e.fails++
	threshold := e.Threshold
	if threshold <= 0 {
		threshold = EgressBlockThreshold
	}
	if e.fails < threshold {
		return domain.EgressReachDegraded, reachCheck(domain.EgressReachDegraded,
			fmt.Sprintf("egress failing (%d/%d) — treating as transient", e.fails, threshold))
	}

	// Persistent failure: actively confirm whether the WARP path is reachable.
	if confirm == nil {
		return domain.EgressReachDegraded, reachCheck(domain.EgressReachDegraded,
			"egress failing but no path confirmation available")
	}
	conf := confirm(ctx)
	if conf.OK {
		// Tunnel still handshakes ⇒ the block is downstream of WARP, not the path.
		return domain.EgressReachDegraded, reachCheck(domain.EgressReachDegraded,
			"egress failing but WARP path reachable ("+conf.Detail+") — downstream, not a block")
	}
	return domain.EgressReachBlocked, reachCheck(domain.EgressReachBlocked,
		"WARP path unreachable ("+conf.Detail+") — likely ISP/DPI block")
}

// findCheck returns the named check from a result set.
func findCheck(checks []domain.HealthCheck, name string) (domain.HealthCheck, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return domain.HealthCheck{}, false
}

// reachCheck builds the egress-reachability self-check. OK is false ONLY for a
// blocked classification, so downstream consumers (UI badge, metrics) flag a
// censorship block off the boolean without parsing the detail.
func reachCheck(class domain.EgressReachability, detail string) *domain.HealthCheck {
	return &domain.HealthCheck{
		Name:   domain.CheckEgressReachability,
		OK:     class != domain.EgressReachBlocked,
		Detail: string(class) + ": " + detail,
	}
}
