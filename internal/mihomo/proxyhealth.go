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
	History []clashDelay `json:"history"`
}

type clashDelay struct {
	Time  time.Time `json:"time"`
	Delay int       `json:"delay"` // milliseconds; 0 on a failed test
}

// ParseProxyHealth extracts per-exit health from a Clash /proxies payload. For
// each name in exitNames it reads the proxy's alive flag and its most recent
// delay test, and marks it selected when it is the current pick of the group
// proxy named groupName (the wg-best load balancer). An exit absent from the
// payload yields a down entry. Order follows exitNames.
func ParseProxyHealth(proxiesJSON []byte, groupName string, exitNames []string) ([]domain.ExitTunnelHealth, error) {
	var cp clashProxies
	if err := json.Unmarshal(proxiesJSON, &cp); err != nil {
		return nil, fmt.Errorf("parse clash /proxies: %w", err)
	}
	selected := ""
	if g, ok := cp.Proxies[groupName]; ok {
		selected = g.Now
	}
	out := make([]domain.ExitTunnelHealth, 0, len(exitNames))
	for _, name := range exitNames {
		h := domain.ExitTunnelHealth{Name: name, Selected: name == selected}
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
