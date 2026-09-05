package mihomo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// ChangedProxies names the proxies whose definition differs between two rendered
// mihomo configs — added, removed, or altered.
//
// A Clash API hot reload (PUT /configs) updates rules, DNS, the sniffer and proxy-
// GROUP membership in place, but it does NOT re-initialise an existing wireguard
// outbound's underlying device, so a change to a proxy's AmneziaWG params
// (S1-S4 / H / keys / endpoint / MTU) silently does not take effect until the
// container is fully restarted (verified live: a hot reload left stale S4 on the
// proxies; only `docker compose restart mihomo` applied them).
//
// It returns NAMES rather than a bare bool because a restart drops every client's
// connection, and "why" is not a nicety. On 2026-09-04 the master bounced twice in
// 36 seconds and the reason could not be reconstructed afterwards from anything on
// the box — the rendered config is not kept, and the controller's journal in that
// window was 97% one unrelated line.
//
// Unparseable input is deliberately asymmetric. A NEW config we cannot parse, or a
// pair that disagree about parseability, forces a restart: we cannot tell what
// changed, so we assume the worst. Two CONSECUTIVELY unparseable configs do not —
// they are equal, and calling that a change would restart mihomo on every pass,
// which is a repeating data-plane outage rather than a safety measure.
func ChangedProxies(oldCfg, newCfg []byte) []string {
	oldP, oldOK := proxiesByName(oldCfg)
	newP, newOK := proxiesByName(newCfg)
	if !oldOK || !newOK {
		if oldOK == newOK {
			return nil
		}
		return []string{"<unparseable>"}
	}
	var changed []string
	for name, want := range newP {
		if got, ok := oldP[name]; !ok || got != want {
			changed = append(changed, name)
		}
	}
	for name := range oldP {
		if _, ok := newP[name]; !ok {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	return changed
}

// ProxiesChanged reports whether the `proxies:` section differs at all. Kept as the
// predicate most callers want; ChangedProxies is what a caller uses when it has to
// say WHICH.
func ProxiesChanged(oldCfg, newCfg []byte) bool {
	return len(ChangedProxies(oldCfg, newCfg)) > 0
}

// proxiesByName indexes the rendered `proxies:` list by proxy name, each value the
// canonical YAML of that one entry. ok is false when the document cannot be parsed
// at all; a document with no proxies parses fine and yields an empty map, which is
// a legitimate state (every exit drained) rather than an error.
func proxiesByName(cfg []byte) (map[string]string, bool) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(cfg, &doc); err != nil {
		return nil, false
	}
	out := make(map[string]string, len(doc.Proxies))
	for i, p := range doc.Proxies {
		name, _ := p["name"].(string)
		if name == "" {
			// Nameless entry: key it by position so it still takes part in the
			// comparison instead of silently collapsing with its siblings.
			name = fmt.Sprintf("<unnamed-%d>", i)
		}
		b, err := yaml.Marshal(p)
		if err != nil {
			return nil, false
		}
		out[name] = string(b)
	}
	return out, true
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

// listenerKeys are the config keys that decide what mihomo BINDS. A change to any
// of them cannot be applied in place.
var listenerKeys = []string{"bind-address", "external-controller", "redir-port", "tproxy-port"}

// ChangedListeners names the listener keys whose value moved between two configs.
//
// It exists for the same reason ChangedProxies does, and for a failure that is one
// step worse. A Clash API hot reload re-reads rules and proxies; it does not
// re-open sockets. So a config whose bind-address moved is accepted, reported as
// applied, and changes nothing — mihomo goes on listening where it was. When the
// address it moved to is in another network namespace, that means the interception
// rules point at listeners that are not there: TCP to a refused connection, UDP
// into the fail-closed drop. Every client's traffic, silently, with the API
// answering 200.
//
// The caller restarts the container instead, exactly as it does for a proxy
// change, and for the same underlying reason: some things are decided at startup.
func ChangedListeners(oldCfg, newCfg []byte) []string {
	oldL, oldOK := listenersOf(oldCfg)
	newL, newOK := listenersOf(newCfg)
	if !oldOK || !newOK {
		if oldOK == newOK {
			return nil
		}
		return []string{"<unparseable>"}
	}
	var changed []string
	for _, k := range listenerKeys {
		if oldL[k] != newL[k] {
			changed = append(changed, k)
		}
	}
	return changed
}

// listenersOf reads the listener keys as strings. Values are formatted rather than
// compared as typed values so an int port and a string port do not read as a
// change; ok is false only when the document will not parse at all.
func listenersOf(cfg []byte) (map[string]string, bool) {
	var doc map[string]any
	if err := yaml.Unmarshal(cfg, &doc); err != nil {
		return nil, false
	}
	out := make(map[string]string, len(listenerKeys))
	for _, k := range listenerKeys {
		if v, ok := doc[k]; ok {
			out[k] = fmt.Sprint(v)
		}
	}
	return out, true
}
