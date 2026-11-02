package mihomo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// DefaultProbeURLs are the destinations a member is probed against to decide
// whether it is genuinely usable.
//
// One URL is not enough. mihomo's own group health check dials a single
// lightweight target, which censorship defeats trivially: an exit under a
// destination-scoped block (or RKN's volume-freeze, which lets small responses
// through and stalls real transfers) answers that one probe fast while every real
// site times out through it. Seen in practice: an exit returned
// cp.cloudflare.com/generate_204 in 113ms while google, github, youtube and
// telegram were 0/16 through the same proxy — and mihomo kept it in rotation
// because, by its measure, it was healthy.
//
// So the set is deliberately spread across independent operators and likely-blocked
// destinations, not just the cheapest reachable one. A member that answers only the
// Cloudflare probe is exactly the failure this list exists to catch.
var DefaultProbeURLs = []string{
	"http://cp.cloudflare.com/generate_204",
	"http://www.gstatic.com/generate_204",
	"http://www.google.com/generate_204",
	"http://detectportal.firefox.com/success.txt",
}

// ProbePhaseBudget bounds the WHOLE probing phase of a reconcile pass, not one
// member.
//
// It exists because the phases stack. Every 10th pass the tier decision, the warm
// probe of the inactive tier and the standby-transport sweep all run together: on
// a mid-sized fleet that is easily 3 primary + 3 reserve + 5 standby = 11 members
// probed back to back. Each member is bounded by one probeTimeout, so a fleet where
// a probe destination is blocked costs 11 x 8s = 88s — three times the 30s reconcile
// interval, and past it the status report that feeds WgfleetNodeReportStale
// (critical at 180s) starts sliding. A per-member bound is not a bound on the pass.
//
// Deliberately well under the interval: the phase gives up rather than making the
// pass late, and a phase that ran out of budget simply leaves the previous verdicts
// standing, which is what every probe path here already does on a blind sample.
const ProbePhaseBudget = 20 * time.Second

// probeTimeout bounds one member×URL probe. Generous enough that a slow-but-usable
// exit is not failed for latency alone (that is the throughput watchdog's job), tight
// enough that a full sweep stays well inside a reconcile pass.
const probeTimeout = 6 * time.Second

// ProbeAttemptBudget is the wall clock ONE ProbeMember call can occupy: its URLs run
// concurrently, so the whole member costs one probeOne bound, not len(urls) of them.
//
// It exists so the phase can decide whether it still has room for a member BEFORE
// starting it. That is the only safe way to bound the phase: a delay test cut short
// is a delay test that writes alive=false (see the result loop in ProbeMember), so
// the phase must skip a member it has no time for, never abandon one mid-flight.
const ProbeAttemptBudget = probeTimeout + 2*time.Second

// enough is the reachable count at which a member is considered proven usable. It
// mirrors the tier selector's threshold; the selector re-checks what it got, so
// keeping the two in step is a convenience rather than a correctness requirement.
// It does NOT stop the probe early — see the comment on the result loop.
const enough = 2

// ProbeMember reports how many of urls the named proxy could reach, by asking
// mihomo to dial each one THROUGH that proxy (Clash API `GET /proxies/{name}/delay`).
//
// Probing through mihomo rather than from the agent directly is what makes this
// meaningful: it measures the exact path client traffic takes, including the exit's
// egress, instead of the master's own connectivity. Returns the reachable count and
// the number attempted; a transport error talking to the API is returned as an error
// so the caller can hold its current decision rather than act on a blind sample.
func ProbeMember(ctx context.Context, controllerAddr, secret, name string, urls []string) (ok, total int, err error) {
	if controllerAddr == "" {
		return 0, 0, fmt.Errorf("%w: no external-controller configured", ErrUnreachable)
	}
	if len(urls) == 0 {
		urls = DefaultProbeURLs
	}

	// Probe concurrently. Sequentially this costs len(urls) × probeTimeout in the
	// worst case (~32s for the default set), which on a 30s reconcile interval means
	// a sick fleet makes passes overlap — the pathology this whole change exists to
	// avoid. Fanning out bounds the wall clock at one timeout.
	type result struct {
		reached bool
		err     error
	}
	results := make(chan result, len(urls))
	// Cancelled on the way out, once every result is in. It releases whatever is
	// still held by a goroutine whose send already completed; it must NOT be used to
	// abandon a probe mid-flight, because a cancelled delay test writes alive=false
	// on the proxy (see the result loop below).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, target := range urls {
		go func(target string) {
			reached, perr := probeOne(ctx, controllerAddr, secret, name, target)
			results <- result{reached, perr}
		}(target)
	}

	// Read EVERY result before deciding. The obvious optimisation — return as soon
	// as `enough` destinations answered — is what made this probe lie to mihomo.
	//
	// `GET /proxies/{name}/delay` is not a read: adapter.Proxy.URLTest stores
	// `alive = (err == nil)` in a defer, unconditionally, for every call. Returning
	// early runs the deferred cancel() above, which cancels the in-flight HTTP
	// requests, which cancels the dials on mihomo's side — so each abandoned probe
	// writes alive=false on the proxy this call is about to report HEALTHY. In a
	// load-balance group that is an eviction, and under consistent-hashing the
	// destinations pinned to that exit move to another one with a different egress
	// address until the group's own check (30s) puts it back.
	//
	// It also bought almost nothing. The probes run concurrently, so waiting for all
	// of them is still bounded by ONE timeout rather than len(urls) of them, and on
	// a healthy member they all answer within a few milliseconds of each other. The
	// cost is paid only on a member that is genuinely failing — where being slow is
	// the correct behaviour anyway.
	var firstErr error
	for range urls {
		r := <-results
		if r.err != nil {
			// The API itself is unreachable — the whole sample is untrustworthy, not
			// just this URL. Remember it rather than counting a failed destination,
			// which would look like the exit is blocked.
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		total++
		if r.reached {
			ok++
		}
	}
	if firstErr != nil && ok == 0 {
		// Nothing usable was observed AND the API misbehaved: report the error so the
		// caller holds its current decision instead of reading this as "exit is down".
		return ok, total, firstErr
	}
	return ok, total, nil
}

// probeOne asks mihomo to dial target through the named proxy. A non-2xx response
// means mihomo tried and failed (timeout/blocked) — that is a real signal about the
// exit, not an API error, so it returns reached=false with no error.
func probeOne(ctx context.Context, controllerAddr, secret, name, target string) (bool, error) {
	q := url.Values{}
	q.Set("url", target)
	q.Set("timeout", fmt.Sprint(probeTimeout.Milliseconds()))
	endpoint := "http://" + controllerAddr + "/proxies/" + url.PathEscape(name) + "/delay?" + q.Encode()

	// Bound each call slightly above the timeout handed to mihomo, so the HTTP call
	// outlives the dial it is waiting on and we read mihomo's verdict instead of
	// timing out on our own side.
	ctx, cancel := context.WithTimeout(ctx, probeTimeout+2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("mihomo probe: build request: %w", err)
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, nil // mihomo dialed and failed: a genuine "unreachable" verdict
	}
	var body struct {
		Delay int `json:"delay"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, nil
	}
	// mihomo reports delay 0 for a probe that did not complete.
	return body.Delay > 0, nil
}
