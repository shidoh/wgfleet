// Package dnsfilter renders the on-node filtering resolver (blocky) config from
// a DNSFilterSpec, plus the docker-compose stack that runs it (ADR-0013). The
// resolver binds loopback and the mgmt/ZT address only, never the public
// interface (docs/DESIGN.md §9): the bind addresses are the primary enforcement of
// "port 53 is reachable on the overlay only".
//
// Only safety/structural fields are first-class. The rich blocky surface
// (denylists, conditional split-horizon mappings, caching tuning, extra upstream
// groups) is layered on by deep-merging the operator's Custom.Overrides into the
// rendered base, exactly like the mihomo renderer — a base built from desired
// state, customized via overrides, never a fork per option.
package dnsfilter

import (
	"fmt"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

const (
	// DefaultDNSPort is blocky's plain-DNS listen port.
	DefaultDNSPort = 53
	// DefaultTLSPort is blocky's DNS-over-TLS listen port.
	DefaultTLSPort = 853
	// DefaultHTTPPort is blocky's HTTP API/metrics port.
	DefaultHTTPPort = 4000

	loopbackAddr = "127.0.0.1"
)

// defaultUpstreams reproduce the operator's privacy-respecting DoT/DoH set; used
// when the spec lists none.
var defaultUpstreams = []string{
	"tcp-tls:dns.quad9.net:853",
	"tcp-tls:dns.mullvad.net:853",
	"https://dns.digitale-gesellschaft.ch/dns-query",
}

// defaultBootstrap resolves the DoT/DoH upstream hostnames above before the
// resolver is serving.
var defaultBootstrap = []domain.BootstrapUpstream{
	{Upstream: "tcp-tls:dns.quad9.net", IPs: []string{"9.9.9.9", "149.112.112.112"}},
	{Upstream: "tcp-tls:dns.mullvad.net", IPs: []string{"194.242.2.2"}},
}

// platformAllowlist holds control-plane domains the fleet must never block. It
// is always merged into the security allowlist so a node cannot filter its own
// management plane (ZeroTier overlay, AmneziaWG infra).
var platformAllowlist = []string{
	"zerotier.com",
	"*.zerotier.com",
	"download.zerotier.com",
	"*.amnezia.org",
}

// RenderBlocky renders blocky's config.yml from spec. It errors when the filter
// is enabled without a mgmt address, since binding the wrong interface (or all
// of them) would expose the resolver publicly.
func RenderBlocky(spec domain.DNSFilterSpec) (string, error) {
	if !spec.Enabled {
		return "", fmt.Errorf("dnsfilter render: filter is disabled")
	}
	if spec.MgmtAddr == "" {
		return "", fmt.Errorf("dnsfilter render: mgmt address is required (bind mgmt/ZT only, never public)")
	}

	upstreams := spec.Upstreams
	if len(upstreams) == 0 {
		upstreams = defaultUpstreams
	}
	bootstrap := spec.BootstrapDNS
	if len(bootstrap) == 0 {
		bootstrap = defaultBootstrap
	}

	base := map[string]any{
		"log":              map[string]any{"level": "warn"},
		"connectIPVersion": "v4",
		"bootstrapDns":     bootstrapList(bootstrap),
		"upstreams": map[string]any{
			"groups": map[string]any{"default": toAnySlice(upstreams)},
		},
		"caching": map[string]any{
			"minTime":           "5m",
			"prefetching":       true,
			"prefetchThreshold": 15,
		},
		"ports": portsMap(spec.MgmtAddr, spec.Ports),
		// allowlists protect the control plane and operator domains even when no
		// denylists are configured; clientGroupsBlock starts empty (no filtering
		// by default — the operator adds denylists + groups via overrides).
		"blocking": map[string]any{
			"allowlists": map[string]any{
				"security": toAnySlice(allowlist(spec.Allowlist)),
			},
			"clientGroupsBlock": map[string]any{"default": []any{}},
		},
	}
	if spec.Prometheus {
		base["prometheus"] = map[string]any{"enable": true, "path": "/metrics"}
	}

	merged := deepMerge(base, spec.Custom.Overrides)

	out, err := marshalYAML(merged)
	if err != nil {
		return "", fmt.Errorf("dnsfilter render: %w", err)
	}
	return "# Rendered by wgfleet — do not edit by hand.\n" + out, nil
}

// portsMap binds each enabled protocol on loopback + the mgmt address only. This
// is what keeps :53 (and the rest) off the public interface.
func portsMap(mgmt string, p domain.DNSPorts) map[string]any {
	dns := p.DNS
	if dns == 0 {
		dns = DefaultDNSPort
	}
	out := map[string]any{"dns": binds(mgmt, dns)}
	tls := p.TLS
	if tls == 0 {
		tls = DefaultTLSPort
	}
	if tls > 0 {
		out["tls"] = binds(mgmt, tls)
	}
	if p.HTTPS > 0 {
		out["https"] = binds(mgmt, p.HTTPS)
	}
	httpPort := p.HTTP
	if httpPort == 0 {
		httpPort = DefaultHTTPPort
	}
	if httpPort > 0 {
		out["http"] = binds(mgmt, httpPort)
	}
	return out
}

// binds returns the loopback + mgmt-address listen list for a port.
func binds(mgmt string, port int) []any {
	return []any{
		fmt.Sprintf("%s:%d", loopbackAddr, port),
		fmt.Sprintf("%s:%d", mgmt, port),
	}
}

func bootstrapList(in []domain.BootstrapUpstream) []any {
	out := make([]any, 0, len(in))
	for _, b := range in {
		entry := map[string]any{"upstream": b.Upstream}
		if len(b.IPs) > 0 {
			entry["ips"] = toAnySlice(b.IPs)
		}
		out = append(out, entry)
	}
	return out
}

// allowlist merges the platform self-protection set with the operator's, keeping
// platform first and de-duplicating.
func allowlist(operator []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range append(append([]string(nil), platformAllowlist...), operator...) {
		d = strings.TrimSpace(d)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func marshalYAML(v any) (string, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		// Close flushes the final node; a truncated flush would write a corrupt
		// config to disk. Surface it instead of shipping invalid YAML.
		return "", fmt.Errorf("flush yaml: %w", err)
	}
	return b.String(), nil
}
