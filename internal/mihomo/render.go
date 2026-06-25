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

// REALITY/XHTTP client defaults (ADR-0025) for a vless proxy when the tunnel
// leaves them unset.
const (
	// DefaultRealityFingerprint is the uTLS ClientHello fingerprint mihomo mimics.
	DefaultRealityFingerprint = "chrome"
	// DefaultXHTTPMode splits the upload into many short POSTs ("packet-up"),
	// which dodges the foreign-DC single-connection volume-freeze and works
	// without a CDN (direct to the exit IP). Set explicitly on both ends because
	// auto+REALITY has an xray bug (#5635).
	DefaultXHTTPMode = "packet-up"
)

// DefaultHealthInterval is the wg-best health-check cadence (seconds) when the spec
// leaves HealthCheckInterval unset.
const DefaultHealthInterval = 60

// External web dashboard for the Clash/mihomo RESTful API. When the API
// (external-controller) is exposed, mihomo can also serve a static dashboard from
// externalUIDir and fetch it on first run from externalUIURL via a DIRECT detour
// (the master reaches GitHub on its own RU/direct path, not through an exit).
const (
	externalUIDir = "ui" // relative to mihomo's -d dir ⇒ /etc/mihomo/ui; served at /ui
	// DefaultDashboardURL is the built-in dashboard source (metacubexd, pinned). A
	// pinned release (not "latest") keeps deploys reproducible; bump deliberately.
	// Operators can override it per master (MasterSpec.DashboardURL) with a mirror
	// reachable from their network, or a different version/dashboard.
	DefaultDashboardURL = "https://github.com/MetaCubeX/metacubexd/releases/download/v1.256.0/compressed-dist.tgz"
)

// GEO database sources. The default mihomo geox URLs point at GitHub raw, which is
// frequently throttled/blocked from a Russian master; the jsdelivr mirror is far
// more reliable. Only emitted when geo rules are actually used (DirectGeo set),
// otherwise mihomo would download geodata it never references.
const (
	geoIPURL   = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
	geoSiteURL = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
)

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

	healthInterval := in.Spec.HealthCheckInterval
	if healthInterval <= 0 {
		healthInterval = DefaultHealthInterval
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
		"proxy-groups": []any{wgBestGroup(lbMembers, in.Spec.Balance, healthInterval)},
		"rules":        renderRules(in.Spec),
	}
	if in.Spec.ExternalController != "" {
		base["external-controller"] = in.Spec.ExternalController
		// Serve the web dashboard alongside the API unless the operator disabled it.
		// Set an API `secret` via mihomo overrides to authenticate it — the controller
		// binds the mgmt/ZT overlay, but the RESTful API is otherwise unauthenticated.
		//
		// We emit external-ui (the dir to serve) but deliberately NOT external-ui-url:
		// the AGENT downloads and unpacks the dashboard into that dir (see master
		// dashboardPlanner). mihomo's own download follows the proxy rules (MATCH →
		// wg-best → exit → WARP) and its external-ui-download-detour is not honored by
		// the running build, so on a blocked/RU master the download TLS-times-out even
		// though the host reaches GitHub directly. Letting the agent fetch it (host has
		// the direct path) and having mihomo only serve the static dir sidesteps that
		// entirely. DashboardURL/DashboardDisabled drive the agent, not this config.
		if !in.Spec.DashboardDisabled {
			base["external-ui"] = externalUIDir
		}
	}

	// GEOSITE/GEOIP rules need geo databases. Configure a reliable mirror and the
	// dat format only when geo rules are actually emitted (DirectGeo set).
	if len(in.Spec.DirectGeo) > 0 {
		base["geodata-mode"] = true
		base["geo-auto-update"] = true
		base["geo-update-interval"] = 24
		base["geox-url"] = map[string]any{
			"geoip":   geoIPURL,
			"geosite": geoSiteURL,
		}
	}

	merged := deepMerge(base, in.Spec.Custom.Overrides)

	// Defense-in-depth: mihomo must never proxy a connection destined to its own redir
	// bind address. The bind IP (e.g. 10.73.0.1) falls under direct-networks' 10/8, so
	// anything that reaches the redir port locally would be matched DIRECT and dialed
	// straight back into the redir port — a self-amplifying connection storm that pins
	// the master's CPU. Reject it as the FIRST rule, injected AFTER the override merge
	// so an operator `rules` override (which replaces the list) cannot drop the guard.
	if bindHost := strings.TrimSpace(in.Spec.BindAddress); bindHost != "" {
		bits := 32
		if ip := net.ParseIP(bindHost); ip != nil && ip.To4() == nil {
			bits = 128
		}
		reject := fmt.Sprintf("IP-CIDR,%s/%d,REJECT,no-resolve", bindHost, bits)
		existing, _ := merged["rules"].([]any)
		merged["rules"] = append([]any{reject}, existing...)
	}

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
		var proxy map[string]any
		switch t.Transport.OrDefault() {
		case domain.TransportRealityXHTTP:
			proxy, perr = realityProxy(t, host, port)
		default: // TransportAWG (empty == awg, back-compat)
			proxy, perr = wireguardProxy(t, host, port, in.PrivateKey)
		}
		if perr != nil {
			return nil, nil, perr
		}
		proxies = append(proxies, proxy)
		if !t.Drained {
			lbMembers = append(lbMembers, t.Name)
		}
	}
	return proxies, lbMembers, nil
}

// wireguardProxy renders a mihomo WireGuard proxy carrying the AmneziaWG-obfuscated
// master↔exit tunnel (TransportAWG).
func wireguardProxy(t domain.ExitTunnel, host string, port int, privateKey string) (map[string]any, error) {
	if t.ServerPublicKey == "" {
		return nil, fmt.Errorf("exit %q: missing server public key", t.Name)
	}
	peer := map[string]any{
		"server":      host,
		"port":        port,
		"public-key":  t.ServerPublicKey,
		"allowed-ips": []any{"0.0.0.0/0"},
	}
	if t.PresharedKey != "" {
		peer["pre-shared-key"] = t.PresharedKey
	}
	proxy := map[string]any{
		"name":        t.Name,
		"type":        "wireguard",
		"ip":          t.TunnelIP,
		"private-key": privateKey,
		"udp":         true,
		// Keepalive is a PROXY-level field in mihomo (WireGuardOption); the peer
		// struct has no such field, so a peer-level value is silently dropped and
		// the master↔exit tunnel would idle out behind NAT.
		"persistent-keepalive": 25,
		"peers":                []any{peer},
	}
	if t.MTU > 0 {
		proxy["mtu"] = t.MTU
	}
	if t.AWG != nil {
		if verr := t.AWG.ValidateUserspace(); verr != nil {
			return nil, fmt.Errorf("exit %q AWG: %w", t.Name, verr)
		}
		proxy["amnezia-wg-option"] = awgOption(*t.AWG)
	}
	return proxy, nil
}

// realityProxy renders a mihomo VLESS proxy carrying REALITY over XHTTP
// (TransportRealityXHTTP, ADR-0025). No `flow` is set: xtls-rprx-vision is
// incompatible with XHTTP. `client-fingerprint` is a top-level key (uTLS
// ClientHello), NOT under reality-opts. The XHTTP mode is set explicitly
// (packet-up) because auto+REALITY has an xray bug (#5635).
func realityProxy(t domain.ExitTunnel, host string, port int) (map[string]any, error) {
	r := t.Reality
	if r == nil {
		return nil, fmt.Errorf("exit %q: reality transport but no reality params", t.Name)
	}
	switch {
	case r.UUID == "":
		return nil, fmt.Errorf("exit %q: reality tunnel missing uuid", t.Name)
	case r.PublicKey == "":
		return nil, fmt.Errorf("exit %q: reality tunnel missing public key", t.Name)
	case r.ServerName == "":
		return nil, fmt.Errorf("exit %q: reality tunnel missing server name (SNI)", t.Name)
	}
	mode := r.XHTTPMode
	if mode == "" {
		mode = DefaultXHTTPMode
	}
	xhttp := map[string]any{"mode": mode}
	if r.XHTTPPath != "" {
		xhttp["path"] = r.XHTTPPath
	}
	// EmptySNI: send the ClientHello with no SNI by setting servername to the exit
	// IP placeholder (uTLS omits the SNI extension for a literal IP). The inbound
	// must accept "" in serverNames (RealityServerSpec.AllowEmptySNI).
	servername := r.ServerName
	if r.EmptySNI {
		servername = host
	}
	proxy := map[string]any{
		"name":       t.Name,
		"type":       "vless",
		"server":     host,
		"port":       port,
		"uuid":       r.UUID,
		"network":    "xhttp",
		"tls":        true,
		"udp":        true,
		"servername": servername,
		"reality-opts": map[string]any{
			"public-key": r.PublicKey,
			"short-id":   r.ShortID,
		},
		"xhttp-opts": xhttp,
	}
	// client-fingerprint is the uTLS ClientHello fingerprint. "none" omits it (the
	// Go-default fingerprint, reported to survive RU TSPU where chrome is flagged);
	// empty ⇒ the chrome default for back-compat.
	if fp := r.Fingerprint; fp != "none" {
		if fp == "" {
			fp = DefaultRealityFingerprint
		}
		proxy["client-fingerprint"] = fp
	}
	return proxy, nil
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

// urlTestToleranceMS is the latency hysteresis for the url-test group: a better
// exit must beat the current one by more than this to trigger a switch. Tunnel
// round-trips are inherently high (full WG path to the probe — an earlier finding), so a
// generous tolerance prevents flapping between two similar exits.
const urlTestToleranceMS = 150

// wgBestGroup renders the master's exit-selection group. `balance` selects the
// mihomo group kind: url-test (lowest-latency exit) and fallback (first-healthy,
// ordered) are their own group TYPES; everything else is a load-balance with the
// given strategy (round-robin default, or consistent-hashing / sticky-sessions).
// All kinds share the same health check (url/interval) that detects dead exits.
// healthInterval is the check cadence in seconds.
func wgBestGroup(names []string, balance string, healthInterval int) map[string]any {
	g := map[string]any{
		"name":     "wg-best",
		"proxies":  toAnySlice(names),
		"url":      "http://cp.cloudflare.com/generate_204",
		"interval": healthInterval,
		"lazy":     false,
	}
	switch balance {
	case "url-test":
		g["type"] = "url-test"
		g["tolerance"] = urlTestToleranceMS
	case "fallback":
		g["type"] = "fallback"
	default:
		g["type"] = "load-balance"
		strategy := balance
		if strategy == "" {
			strategy = "round-robin"
		}
		g["strategy"] = strategy
	}
	return g
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
	if err := enc.Close(); err != nil {
		// Close flushes the final node; a truncated flush would write a corrupt
		// config to disk. Surface it instead of shipping invalid YAML.
		return "", fmt.Errorf("flush yaml: %w", err)
	}
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
