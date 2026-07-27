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
		"ports": portsMap(bindAddrs(spec), spec.Ports),
		// allowlists protect the control plane and operator domains even when no
		// denylists are configured; clientGroupsBlock starts empty (no filtering
		// by default — the operator adds denylists + groups via overrides).
		"blocking": map[string]any{
			// Answer blocked A/AAAA with NXDOMAIN, not blocky's zeroIP default. In a
			// proxied fleet 0.0.0.0 is a trap: the client treats it as a real answer and
			// dials it, the connection matches the catch-all rule and is handed to the
			// wg-best proxy group, and mihomo counts the inevitable failure AGAINST THE
			// GROUP. Measured on the live master 2026-07-27: ~8400 bogus
			// "dial wg-best ... connect tcp 0.0.0.0:443: connection was refused" and 1625
			// "because wg-best failed multiple times, activate health check" in three
			// hours — roughly 47 and 9 per minute, forever. That pollutes the exact health
			// signal tiered exit selection reads to decide whether to fail over to the
			// reserve tier, so a node's apparent health tracked how much ad traffic the
			// clients generated. NXDOMAIN says the name does not exist, so the client
			// never dials and no exit is blamed for a block we chose ourselves.
			// Overridable per node via the spec's blocky overrides.
			"blockType": "nxDomain",
			// blocky's default blockTTL is 6h, which bounds how long a STALE decision
			// survives in client caches — in both directions. Switching blockType took
			// ~8 minutes to take effect fleet-wide purely because clients still held the
			// old answer, and the worse case is un-blocking: drop a domain from a denylist
			// and it stays unreachable for the rest of the day. A blocked answer is
			// generated locally from the in-memory list and never touches an upstream, so
			// a short TTL costs nothing but a few more local queries.
			"blockTTL": "1m",
			"allowlists": map[string]any{
				"security": inlineList(allowlist(spec.Allowlist)),
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

// bindAddrs is the ordered list of non-loopback addresses blocky binds: the
// mgmt/ZT address, plus the client-pool gateway on a master-tier resolver
// (ADR-0024). Both are internal (overlay / tunnel-internal); the public interface
// is never in this list — that is the enforcement of "port 53 stays off the
// public IP".
func bindAddrs(spec domain.DNSFilterSpec) []string {
	addrs := []string{spec.MgmtAddr}
	if a := strings.TrimSpace(spec.ClientBindAddr); a != "" && a != spec.MgmtAddr {
		addrs = append(addrs, a)
	}
	return addrs
}

// portsMap binds each enabled protocol on loopback + the given internal addresses
// only. This is what keeps :53 (and the rest) off the public interface.
func portsMap(addrs []string, p domain.DNSPorts) map[string]any {
	dns := p.DNS
	if dns == 0 {
		dns = DefaultDNSPort
	}
	out := map[string]any{"dns": binds(addrs, dns)}
	tls := p.TLS
	if tls == 0 {
		tls = DefaultTLSPort
	}
	if tls > 0 {
		out["tls"] = binds(addrs, tls)
	}
	if p.HTTPS > 0 {
		out["https"] = binds(addrs, p.HTTPS)
	}
	httpPort := p.HTTP
	if httpPort == 0 {
		httpPort = DefaultHTTPPort
	}
	if httpPort > 0 {
		out["http"] = binds(addrs, httpPort)
	}
	return out
}

// binds returns the loopback + internal-address listen list for a port.
func binds(addrs []string, port int) []any {
	out := make([]any, 0, len(addrs)+1)
	out = append(out, fmt.Sprintf("%s:%d", loopbackAddr, port))
	for _, a := range addrs {
		out = append(out, fmt.Sprintf("%s:%d", a, port))
	}
	return out
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

// inlineList renders domains as a blocky INLINE list source: a single list entry
// holding all domains separated by newlines (yaml emits it as a block scalar).
// Each entry in a blocky denylist/allowlist group is a SOURCE reference — a bare
// domain string would be read as a file path (`file://domain`) and fail to load,
// silently emptying the group. The inline form is the only way to embed literal
// domains. Returns an empty list when there are no domains.
func inlineList(domains []string) []any {
	if len(domains) == 0 {
		return []any{}
	}
	return []any{strings.Join(domains, "\n")}
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
