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
// site times out through it. Observed live 2026-07-19: an exit returned
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

// probeTimeout bounds one member×URL probe. Generous enough that a slow-but-usable
// exit is not failed for latency alone (that is the throughput watchdog's job), tight
// enough that a full sweep stays well inside a reconcile pass.
const probeTimeout = 6 * time.Second

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

	for _, target := range urls {
		reached, perr := probeOne(ctx, controllerAddr, secret, name, target)
		if perr != nil {
			// The API itself is unreachable — the whole sample is untrustworthy, not
			// just this URL. Report it rather than counting it as a failed destination,
			// which would look like the exit is blocked.
			return ok, total, perr
		}
		total++
		if reached {
			ok++
		}
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
