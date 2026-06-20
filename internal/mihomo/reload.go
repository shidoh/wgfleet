package mihomo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// ProxiesChanged reports whether the `proxies:` section differs between two
// rendered mihomo configs. A Clash API hot reload (PUT /configs) updates rules,
// DNS, the sniffer and proxy-GROUP membership in place, but it does NOT
// re-initialise an existing wireguard outbound's underlying device — so a change
// to a proxy's AmneziaWG params (S1-S4 / H / keys / endpoint / MTU) silently does
// NOT take effect until the container is fully restarted (verified live: a hot
// reload left stale S4 on the proxies; only `docker compose restart mihomo`
// applied them). The mihomo planner uses this to force a restart on a proxy
// change while still hot-reloading routine changes (drain, rules) that keep every
// client's connection alive. When either side is unparseable (e.g. first run, no
// prior config) it returns true so the agent restarts to be safe.
func ProxiesChanged(oldCfg, newCfg []byte) bool {
	return proxiesYAML(oldCfg) != proxiesYAML(newCfg)
}

func proxiesYAML(cfg []byte) string {
	var doc map[string]any
	if err := yaml.Unmarshal(cfg, &doc); err != nil {
		return "<unparseable>"
	}
	p, ok := doc["proxies"]
	if !ok {
		return "<no-proxies>"
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		return "<unmarshalable>"
	}
	return string(b)
}

// reloadTimeout bounds the Clash API call so a wedged controller never blocks a
// reconcile pass.
const reloadTimeout = 10 * time.Second

// ErrUnreachable wraps a transport-level failure talking to the Clash RESTful API
// (mihomo down, mid-restart, or the controller address unreachable) — as opposed
// to mihomo being up and REJECTING the config. The distinction matters: on
// unreachable the caller may fall back to a container restart, but on a rejected
// config it must NOT (mihomo keeps the previous config running; restarting would
// load the bad file and take the data plane down).
var ErrUnreachable = errors.New("mihomo: clash API unreachable")

// Reload hot-applies cfgYAML to a running mihomo through the Clash RESTful API
// (`PUT /configs` with a payload), so a config change — e.g. draining one exit out
// of the load-balance group — takes effect WITHOUT a container restart that would
// drop every client's connection. force is left false, so mihomo updates proxies,
// groups and rules in place and keeps existing connections; only NEW connections
// see the change (verified against mihomo's executor.ApplyConfig). controllerAddr
// is the external-controller host:port; secret is the Clash API secret (empty ⇒ no
// auth). A transport failure is wrapped as ErrUnreachable; a non-2xx response means
// mihomo rejected the config and is returned as a plain error.
func Reload(ctx context.Context, controllerAddr, secret string, cfgYAML []byte) error {
	if controllerAddr == "" {
		return fmt.Errorf("%w: no external-controller configured", ErrUnreachable)
	}
	body, err := json.Marshal(struct {
		Payload string `json:"payload"`
	}{Payload: string(cfgYAML)})
	if err != nil {
		return fmt.Errorf("mihomo reload: marshal payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, reloadTimeout)
	defer cancel()

	url := "http://" + controllerAddr + "/configs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("mihomo reload: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("mihomo reload: controller rejected config (HTTP %d): %s",
		resp.StatusCode, bytes.TrimSpace(msg))
}
