// Package mihomo renders the master node's mihomo data-plane configuration from
// the desired MasterSpec. mihomo is the master's proxy router + load balancer:
// each exit is a WireGuard proxy carrying an AmneziaWG tunnel (rendered into the
// proxy's `amnezia-wg-option`), grouped under a load-balance group, with
// RU/private destinations routed DIRECT.
//
// The base config is built as a structured map and operator Overrides are
// deep-merged on top (CustomConfig), so operators can inject parameters the
// domain model doesn't promote to first-class fields. Output is deterministic
// (yaml.v3 sorts map keys), which keeps dry-run diffs honest.
package mihomo

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

// DefaultRedirPort is mihomo's redirect port when the spec leaves it unset.
const DefaultRedirPort = 7895

// directNetworksPath is the included rule-provider file mihomo reads for the
// DIRECT ipcidr set. It is provisioned as an extra managed file.
const directNetworksPath = "/etc/mihomo/direct-networks.yaml"

// RenderInput is everything needed to render the mihomo config.
type RenderInput struct {
	Spec domain.MasterSpec
	// PrivateKey is the master's WireGuard private key, injected by the agent at
	// render time and shared across all exit-tunnel proxies (one master identity
	// that each exit peers). Never supplied by the controller.
	PrivateKey string
}

// RenderConfig renders mihomo's config.yaml. It validates each tunnel's AWG
// params for userspace (mihomo is userspace WireGuard, so <c>/<t> tags are
// rejected) before emitting.
func RenderConfig(in RenderInput) (string, error) {
	if in.PrivateKey == "" {
		return "", fmt.Errorf("mihomo render: master private key is required")
	}
	if len(in.Spec.ExitTunnels) == 0 {
		return "", fmt.Errorf("mihomo render: no exit tunnels (no registered exits yet?)")
	}

	proxies, lbMembers, err := renderProxies(in)
	if err != nil {
		return "", err
	}
	if len(lbMembers) == 0 {
		// Every exit is drained: the load-balance group would be empty (invalid)
		// and there would be no egress. Refuse rather than emit a broken config;
		// the operator must keep at least one exit in rotation.
		return "", fmt.Errorf("mihomo render: all exits are drained, the load balancer would be empty")
	}

	redir := in.Spec.RedirPort
	if redir == 0 {
		redir = DefaultRedirPort
	}

	base := map[string]any{
		"mode":         "rule",
		"log-level":    "info",
		"ipv6":         false,
		"allow-lan":    true,
		"bind-address": in.Spec.BindAddress,
		"redir-port":   redir,
		"dns": map[string]any{
			"enable":             true,
			"listen":             "127.0.0.1:1053",
			"ipv6":               false,
			"default-nameserver": []any{"77.88.8.8", "8.8.8.8"},
			"nameserver":         []any{"77.88.8.8", "8.8.8.8"},
		},
		"sniffer": map[string]any{
			"enable":               true,
			"force-dns-mapping":    true,
			"parse-pure-ip":        true,
			"override-destination": true,
			"sniff": map[string]any{
				"HTTP": map[string]any{"ports": []any{80, "8080-8880"}},
				"TLS":  map[string]any{"ports": []any{443, 8443}},
				"QUIC": map[string]any{"ports": []any{443, 8443}},
			},
			"skip-domain": toAnySlice(in.Spec.SnifferSkip),
		},
		"rule-providers": map[string]any{
			"direct-networks": map[string]any{
				"type":     "file",
				"behavior": "ipcidr",
				"path":     directNetworksPath,
				"interval": 60,
			},
		},
		"proxies":      proxies,
		"proxy-groups": []any{loadBalanceGroup(lbMembers, in.Spec.Balance)},
		"rules":        renderRules(in.Spec),
	}
	if in.Spec.ExternalController != "" {
		base["external-controller"] = in.Spec.ExternalController
	}

	merged := deepMerge(base, in.Spec.Custom.Overrides)

	out, err := marshalYAML(merged)
	if err != nil {
		return "", fmt.Errorf("mihomo render: %w", err)
	}
	return out, nil
}

// RenderDirectNetworks renders the included direct-networks.yaml from the spec's
// DirectCIDRs. mihomo loads it as a `file` rule-provider (ipcidr behavior).
func RenderDirectNetworks(spec domain.MasterSpec) (string, error) {
	payload := make([]any, 0, len(spec.DirectCIDRs))
	for _, c := range spec.DirectCIDRs {
		payload = append(payload, c)
	}
	out, err := marshalYAML(map[string]any{"payload": payload})
	if err != nil {
		return "", fmt.Errorf("mihomo render direct-networks: %w", err)
	}
	return out, nil
}

// DirectNetworksPath returns the on-node path of the included file.
func DirectNetworksPath() string { return directNetworksPath }

// renderProxies builds the proxy list and the load-balance member names.
// Drained tunnels are still rendered as proxies (so existing connections via
// them keep working) but excluded from lbMembers, so no new traffic routes to
// them — a graceful drain.
func renderProxies(in RenderInput) (proxies []any, lbMembers []string, err error) {
	for _, t := range in.Spec.ExitTunnels {
		host, port, perr := splitEndpoint(t.Endpoint)
		if perr != nil {
			return nil, nil, fmt.Errorf("exit %q: %w", t.Name, perr)
		}
		if t.ServerPublicKey == "" {
			return nil, nil, fmt.Errorf("exit %q: missing server public key", t.Name)
		}
		peer := map[string]any{
			"server":               host,
			"port":                 port,
			"public-key":           t.ServerPublicKey,
			"allowed-ips":          []any{"0.0.0.0/0"},
			"persistent-keepalive": 25,
		}
		if t.PresharedKey != "" {
			peer["pre-shared-key"] = t.PresharedKey
		}
		proxy := map[string]any{
			"name":        t.Name,
			"type":        "wireguard",
			"ip":          t.TunnelIP,
			"private-key": in.PrivateKey,
			"udp":         true,
			"peers":       []any{peer},
		}
		if t.MTU > 0 {
			proxy["mtu"] = t.MTU
		}
		if t.AWG != nil {
			if verr := t.AWG.ValidateUserspace(); verr != nil {
				return nil, nil, fmt.Errorf("exit %q AWG: %w", t.Name, verr)
			}
			proxy["amnezia-wg-option"] = awgOption(*t.AWG)
		}
		proxies = append(proxies, proxy)
		if !t.Drained {
			lbMembers = append(lbMembers, t.Name)
		}
	}
	return proxies, lbMembers, nil
}

// awgOption renders the mihomo amnezia-wg-option block. H ranges render as
// "min-max" strings (mihomo/AmneziaWG range syntax).
func awgOption(p domain.AWGParams) map[string]any {
	opt := map[string]any{
		"jc":   p.Local.Jc,
		"jmin": p.Local.Jmin,
		"jmax": p.Local.Jmax,
		"s1":   p.Shared.S1,
		"s2":   p.Shared.S2,
		"s3":   p.Shared.S3,
		"s4":   p.Shared.S4,
		"h1":   p.Shared.H1.String(),
		"h2":   p.Shared.H2.String(),
		"h3":   p.Shared.H3.String(),
		"h4":   p.Shared.H4.String(),
	}
	for i, v := range []string{p.Local.I1, p.Local.I2, p.Local.I3, p.Local.I4, p.Local.I5} {
		if v != "" {
			opt[fmt.Sprintf("i%d", i+1)] = v
		}
	}
	return opt
}

func loadBalanceGroup(names []string, strategy string) map[string]any {
	if strategy == "" {
		strategy = "round-robin"
	}
	return map[string]any{
		"name":      "wg-best",
		"type":      "load-balance",
		"strategy":  strategy,
		"proxies":   toAnySlice(names),
		"url":       "http://cp.cloudflare.com/generate_204",
		"interval":  60,
		"lazy":      false,
		"tolerance": 50,
	}
}

func renderRules(spec domain.MasterSpec) []any {
	rules := []any{
		"RULE-SET,direct-networks,DIRECT",
	}
	for _, geo := range spec.DirectGeo {
		rules = append(rules,
			fmt.Sprintf("GEOSITE,category-%s,DIRECT", strings.ToLower(geo)),
			fmt.Sprintf("GEOIP,%s,DIRECT,no-resolve", strings.ToUpper(geo)),
		)
	}
	rules = append(rules, "MATCH,wg-best")
	return rules
}

func splitEndpoint(endpoint string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", 0, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("invalid endpoint port %q: %w", p, err)
	}
	return h, port, nil
}

func toAnySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
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
	_ = enc.Close()
	return b.String(), nil
}

// RedactConfig masks secret key lines (private-key, pre-shared-key) for plan output.
func RedactConfig(cfg string) string {
	var b strings.Builder
	for _, line := range strings.Split(cfg, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "private-key:") || strings.HasPrefix(trimmed, "pre-shared-key:") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
			key := strings.SplitN(trimmed, ":", 2)[0]
			b.WriteString(indent + key + ": <redacted>\n")
			continue
		}
		b.WriteString(line + "\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}
