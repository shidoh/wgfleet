package mihomo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/shidoh/wgfleet/internal/domain"
)

// clashProxies is the subset of the Clash API GET /proxies response we read.
type clashProxies struct {
	Proxies map[string]clashProxy `json:"proxies"`
}

type clashProxy struct {
	Alive   bool         `json:"alive"`
	Now     string       `json:"now"` // for group proxies: the currently selected member
	All     []string     `json:"all"` // for group proxies: the member list
	History []clashDelay `json:"history"`
}

type clashDelay struct {
	Time  time.Time `json:"time"`
	Delay int       `json:"delay"` // milliseconds; 0 on a failed test
}

// maxGroupDepth bounds the walk so a malformed or cyclic group graph can never
// hang a status pass.
const maxGroupDepth = 8

// collectCarrying walks the selection graph from `name` and records every LEAF
// proxy that currently carries traffic.
//
// Two kinds of node are treated differently (ADR-0029):
//   - a group with a `now` (url-test, fallback) hands all traffic to one member,
//     so the walk follows that single edge;
//   - a group without a `now` but with members (load-balance) spreads traffic
//     across every member at once, so ALL of them carry and the walk fans out.
//
// A node that is neither is a leaf proxy — an exit — and is recorded.
func collectCarrying(proxies map[string]clashProxy, name string, depth int, seen, out map[string]struct{}) {
	if depth > maxGroupDepth {
		return
	}
	if _, dup := seen[name]; dup {
		return
	}
	seen[name] = struct{}{}

	p, ok := proxies[name]
	switch {
	case !ok:
		// Not in the payload: treat as a leaf so an unknown name is still reported.
		out[name] = struct{}{}
	case p.Now != "":
		collectCarrying(proxies, p.Now, depth+1, seen, out)
	case len(p.All) > 0:
		for _, member := range p.All {
			collectCarrying(proxies, member, depth+1, seen, out)
		}
	default:
		out[name] = struct{}{}
	}
}

// ParseProxyHealth extracts per-exit health from a Clash /proxies payload. For
// each name in exitNames it reads the proxy's alive flag and its most recent
// delay test, and marks it selected when it currently carries traffic under
// groupName — walking through any nested tier groups (ADR-0029) to the leaf
// exits. An exit absent from the payload yields a down entry. Order follows
// exitNames.
func ParseProxyHealth(proxiesJSON []byte, groupName string, exitNames []string) ([]domain.ExitTunnelHealth, error) {
	var cp clashProxies
	if err := json.Unmarshal(proxiesJSON, &cp); err != nil {
		return nil, fmt.Errorf("parse clash /proxies: %w", err)
	}
	carrying := make(map[string]struct{})
	if _, ok := cp.Proxies[groupName]; ok {
		collectCarrying(cp.Proxies, groupName, 0, make(map[string]struct{}), carrying)
	}
	out := make([]domain.ExitTunnelHealth, 0, len(exitNames))
	for _, name := range exitNames {
		_, isCarrying := carrying[name]
		h := domain.ExitTunnelHealth{Name: name, Selected: isCarrying}
		if p, ok := cp.Proxies[name]; ok {
			h.Alive = p.Alive
			if n := len(p.History); n > 0 {
				last := p.History[n-1]
				h.Delay = time.Duration(last.Delay) * time.Millisecond
				h.LastTest = last.Time.UTC()
			}
		}
		out = append(out, h)
	}
	return out, nil
}

// fetchTimeout bounds a single Clash /proxies read so a wedged mihomo never
// stalls a status pass.
const fetchTimeout = 5 * time.Second

// FetchProxies GETs the Clash API /proxies snapshot. apiAddr is host:port (the
// mihomo external-controller); secret is the Clash API secret (may be empty).
func FetchProxies(ctx context.Context, apiAddr, secret string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	url := "http://" + apiAddr + "/proxies"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build /proxies request: %w", err)
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clash /proxies: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read /proxies body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clash /proxies: status %d", resp.StatusCode)
	}
	return body, nil
}
