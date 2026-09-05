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
	"github.com/shidoh/wgfleet/internal/wg"
)

// TProxyPortFor returns the transparent-UDP listener that pairs with a given
// redirect port.
//
// Redirect handles TCP only, so client UDP had no proxy path at all and leaked out
// the master's own uplink. TPROXY gives it one — but only if the nft rule and
// mihomo agree on the port, and they are rendered by different components on
// different sides of the wire. Deriving both from the redirect port keeps them in
// step through an operator override without adding a second knob to the manifest
// (and a second thing to get wrong).
func TProxyPortFor(redirPort int) int {
	if redirPort == 0 {
		redirPort = DefaultRedirPort
	}
	return redirPort + 1
}

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
	// Bumped v1.256.0 → v1.273.0 (2026-08-17). Most of the intervening work went into
	// metacubexd's new desktop app, which we do not ship; the web side gained a visual
	// profile editor, managed rules/proxies CRUD, a last-week traffic range, and a fix for
	// the memory chart reporting MB/s where it meant MB. compressed-dist.tgz is still the
	// published asset, so the fetch path is unchanged.
	DefaultDashboardURL = "https://github.com/MetaCubeX/metacubexd/releases/download/v1.273.0/compressed-dist.tgz"
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
	// render time. It is the identity for every tunnel that has no MasterKeyTunnel
	// set, and the root the per-tunnel keys are derived from. Never supplied by the
	// controller.
	PrivateKey string
	// TunnelPrivateKey resolves the master's dedicated private key for one tunnel
	// (ADR-0030), called only for tunnels whose ExitTunnel.MasterKeyTunnel is set.
	// The agent supplies it (wg.DeriveTunnelKey over its master key) so RenderConfig
	// stays a pure function of its inputs and no key material is derived here.
	// nil ⇒ per-tunnel keys are unavailable and a tunnel that asks for one is a hard
	// error rather than a silent fall back to the shared key: falling back would
	// render a config the exit's kernel rejects in the `on` phase, i.e. a dead
	// tunnel that looks configured.
	TunnelPrivateKey func(tunnel string) (string, error)
	// ReserveActive routes wg-best to the RESERVE tier instead of the primary one
	// (ADR-0029, revised). The master agent sets it — not the controller — because
	// the decision needs live per-member health that only the master observes, and
	// because mihomo cannot make it itself (see wgBestGroups).
	//
	// It is deliberately NOT on MasterSpec/the wire: keeping it a render input makes
	// RenderConfig a pure function of (spec, key, tier) and keeps failover policy on
	// the node that has the evidence. The agent must debounce it — every flip
	// rewrites config.yaml and reloads mihomo, so a flapping exit would otherwise
	// churn the whole data plane.
	ReserveActive bool
	// NetnsPeerAddr is mihomo's address INSIDE the network namespace it has been
	// moved into. Empty ⇒ mihomo is on host networking and binds the client
	// gateway, which is how it has always worked.
	//
	// It has to be a render input rather than something the controller sets,
	// because whether the move has happened is decided by the agent from evidence
	// on the node. And it has to exist at all because everything mihomo binds is an
	// address on the HOST: the client gateway for its listeners, the management
	// overlay for its API. Neither exists inside the namespace, so a mihomo moved
	// there without this fails every listener with EADDRNOTAVAIL, while the rules
	// in the namespace point at ports nobody is on — TCP refused, UDP into the
	// fail-closed drop, which is every client's traffic.
	NetnsPeerAddr string
	// Resolvers is where mihomo sends its OWN lookups. The agent supplies it, for
	// the same reason ReserveActive is a render input: the answer depends on what is
	// actually running on the node (does this master run blocky?), which the
	// controller cannot see and does not need to.
	//
	// This matters more than it looks. mihomo does not merely forward what the client
	// resolved: with the sniffer recovering the SNI and override-destination on, it
	// re-resolves the hostname itself before dialling the proxy. Those lookups used
	// to go, in cleartext UDP/53 from the master's own address, to a hardcoded public
	// resolver — handing the one uplink the adversary is assumed to watch the full
	// browsing metadata of every user, and a poisoning lever besides. Empty falls
	// back to encrypted public resolvers, never to cleartext.
	Resolvers []string
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

	proxies, primary, reserve, err := renderProxies(in)
	if err != nil {
		return "", err
	}
	if len(primary)+len(reserve) == 0 {
		// Every exit is drained: both tiers would be empty and there would be no
		// egress. Refuse rather than emit a broken config; the operator must keep at
		// least one exit in rotation.
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

	// The fleet's resolver, EXCLUSIVELY when there is one.
	//
	// This briefly listed the public resolvers behind the fleet's own, to keep a
	// resolver that stops answering from taking the data plane down with it. That was
	// wrong about mihomo: `nameserver` is a concurrent POOL, not an ordered fallback —
	// it races every member and takes the first answer. Measured on a rehearsal, the
	// result was permanent DoT connections from the master to 1.1.1.1:853 and
	// 9.9.9.9:853, keepalives and all: a standing signature on the one uplink the
	// censor is assumed to watch, and the full browsing metadata of every user handed
	// to two resolvers outside the fleet. "Faster than blocky" is not a tie-break we
	// want deciding where our users' names get resolved.
	//
	// So a fleet resolver that does not answer is a FAULT, to be reported rather than
	// silently routed around. On a real deployment it is not even a new failure mode:
	// blocky is the clients' only resolver, so a blocky that is down has already taken
	// their DNS with it whatever mihomo does. The public list is for the genuinely
	// resolver-less node, where the alternative is not forwarding at all.
	//
	// mihomo re-resolves the sniffed domain on EVERY proxied connection — measured, a
	// client that did no DNS of its own still produced seven A? queries from the
	// master — so this list is not a convenience, it is a dependency of forwarding.
	resolvers := in.Resolvers
	if len(resolvers) == 0 {
		resolvers = fallbackResolvers
	}

	base := map[string]any{
		"mode":         "rule",
		"log-level":    "info",
		"ipv6":         false,
		"allow-lan":    true,
		"bind-address": in.listenAddr(),
		"redir-port":   redir,
		// Transparent UDP. Redirect cannot carry UDP, so without this every client
		// datagram that was not QUIC-on-443 left the master's own uplink instead of an
		// exit's. The master's nft rules derive the same port from redir-port.
		"tproxy-port": TProxyPortFor(redir),
		"dns": map[string]any{
			"enable": true,
			"listen": "127.0.0.1:1053",
			"ipv6":   false,
			// Both keys get the same list on purpose. default-nameserver exists to
			// resolve the HOSTNAMES of other DNS servers, so with IP-literal resolvers
			// it is inert — but leaving a public resolver sitting in it is a leak
			// waiting for the first hostname-form entry somebody adds later.
			"default-nameserver": toAnySlice(resolvers),
			"nameserver":         toAnySlice(resolvers),
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
		"proxies": proxies,
		"proxy-groups": wgBestGroups(primary, reserve, groupOpts{
			balance:        in.Spec.Balance,
			healthInterval: healthInterval,
			maxFailedTimes: in.Spec.MaxFailedTimes,
		}, in.ReserveActive),
		"rules": renderRules(in.Spec),
	}
	// Client-facing VLESS terminates in xray on the master; its decrypted traffic is
	// forwarded to this loopback SOCKS listener, so VLESS clients traverse the SAME
	// rules / geo / load-balance / exit selection as the AWG clients — one routing
	// brain, no second data plane. Loopback-only: reachable solely from xray on the
	// same host, never from the network.
	//
	// udp: true is REQUIRED. A tun-mode client (v2rayTun) sends DNS over UDP through
	// the tunnel; xray forwards it to this SOCKS outbound, and with udp:false mihomo
	// drops the UDP associate — DNS black-holes and the whole session looks dead
	// ("connects, then nothing resolves"). Enabling UDP lets DNS (and other UDP)
	// route through mihomo. The master's QUIC/UDP-443 drop is a separate nftables
	// concern for the AWG client pool, not this loopback bridge.
	if cv := in.Spec.ClientVLESS; cv != nil {
		base["listeners"] = []any{map[string]any{
			"name":   "client-vless-in",
			"type":   "socks",
			"listen": "127.0.0.1",
			"port":   cv.ResolvedSocksPort(),
			"udp":    true,
		}}
	}
	if in.Spec.ExternalController != "" {
		base["external-controller"] = in.controllerAddr()
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
	if bindHost := strings.TrimSpace(in.listenAddr()); bindHost != "" {
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

// renderProxies builds the proxy list and partitions the non-drained tunnel
// names into the primary and reserve exit-selection tiers (ADR-0029). Drained
// tunnels are still rendered as proxies (so existing connections via them keep
// working) but join neither tier, so no new traffic routes to them — a
// graceful drain.
func renderProxies(in RenderInput) (proxies []any, primary, reserve []string, err error) {
	// A proxy name is the join key between `proxies` and every proxy-group's member
	// list, so two proxies under one name make the tiers ambiguous: mihomo keeps one
	// of them and wg-best then routes to an exit nobody chose. Node names are cert
	// CNs and unique, but the REALITY transport derives "<node>-reality", which a
	// node literally named that way collides with. Refusing to render is the
	// fail-safe: the planner errors and the previous good config keeps running.
	seen := make(map[string]bool, len(in.Spec.ExitTunnels))
	for _, t := range in.Spec.ExitTunnels {
		if seen[t.Name] {
			return nil, nil, nil, fmt.Errorf("duplicate mihomo proxy name %q: two exit tunnels render to the same proxy, so proxy-group members would be ambiguous", t.Name)
		}
		seen[t.Name] = true

		host, port, perr := splitEndpoint(t.Endpoint)
		if perr != nil {
			return nil, nil, nil, fmt.Errorf("exit %q: %w", t.Name, perr)
		}
		var proxy map[string]any
		switch t.Transport.OrDefault() {
		case domain.TransportRealityXHTTP:
			proxy, perr = realityProxy(t, host, port)
		default: // TransportAWG (empty == awg, back-compat)
			key, kerr := masterKeyFor(in, t)
			if kerr != nil {
				return nil, nil, nil, kerr
			}
			proxy, perr = wireguardProxy(t, host, port, key)
		}
		if perr != nil {
			return nil, nil, nil, perr
		}
		proxies = append(proxies, proxy)
	}
	primary, reserve = TierMembers(in.Spec)
	return proxies, primary, reserve, nil
}

// TierMembers partitions the spec's exit tunnels into the primary and reserve
// selection tiers (ADR-0029). A drained exit stays a configured proxy so existing
// connections survive, but joins neither tier, so no new traffic reaches it
// (ADR-0010).
//
// Exported because the master agent needs the same membership the renderer will
// use, in order to probe the primary tier and decide RenderInput.ReserveActive.
// Sharing one function keeps the decision and the rendered config from drifting
// apart — an agent probing a tier that differs from the one it then renders would
// fail over on evidence about the wrong exits.
func TierMembers(spec domain.MasterSpec) (primary, reserve []string) {
	for _, t := range spec.ExitTunnels {
		if t.Drained {
			continue
		}
		if t.Reserve {
			reserve = append(reserve, t.Name)
		} else {
			primary = append(primary, t.Name)
		}
	}
	return primary, reserve
}

// masterKeyFor picks the master's WireGuard private key for one tunnel: the
// dedicated per-tunnel identity when the controller asked for one (ADR-0030),
// otherwise the shared master key.
func masterKeyFor(in RenderInput, t domain.ExitTunnel) (string, error) {
	if t.MasterKeyTunnel == "" {
		return in.PrivateKey, nil
	}
	if in.TunnelPrivateKey == nil {
		return "", fmt.Errorf("exit %q: spec asks for the per-tunnel master key %q but none was supplied",
			t.Name, t.MasterKeyTunnel)
	}
	key, err := in.TunnelPrivateKey(t.MasterKeyTunnel)
	if err != nil {
		return "", fmt.Errorf("exit %q: per-tunnel master key %q: %w", t.Name, t.MasterKeyTunnel, err)
	}
	if key == "" {
		return "", fmt.Errorf("exit %q: empty per-tunnel master key %q", t.Name, t.MasterKeyTunnel)
	}
	return key, nil
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
		"persistent-keepalive": wg.KeepaliveFor("master-exit|master|" + t.ServerPublicKey),
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
		"tls":        true,
		"udp":        true,
		"servername": servername,
		"reality-opts": map[string]any{
			"public-key": r.PublicKey,
			"short-id":   r.ShortID,
		},
	}
	// Transport mode (ADR-0025): vision = classic TCP + xtls-rprx-vision (no XHTTP);
	// xhttp (default) = network xhttp + xhttp-opts, no flow (Vision is incompatible
	// with XHTTP). The switch isolates XHTTP interop / falls back to a known-good path.
	if r.Mode == domain.RealityModeVision {
		proxy["network"] = "tcp"
		proxy["flow"] = "xtls-rprx-vision"
	} else {
		mode := r.XHTTPMode
		if mode == "" {
			mode = DefaultXHTTPMode
		}
		xhttp := map[string]any{"mode": mode}
		if r.XHTTPPath != "" {
			xhttp["path"] = r.XHTTPPath
		}
		// XMUX: reuse the underlying XHTTP connection across requests so the REALITY
		// handshake + dest-steal is amortized (without it mihomo opens a fresh
		// connection — and a fresh handshake — per request). Server-compatible: xray
		// needs no change. Defaults mirror the documented XMUX template.
		if r.Mux {
			xhttp["reuse-settings"] = map[string]any{
				"max-concurrency":     "16-32",
				"h-max-request-times": "600-900",
				"h-max-reusable-secs": "1800-3000",
			}
		}
		proxy["network"] = "xhttp"
		proxy["xhttp-opts"] = xhttp
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

	// AmneziaWG 3.0. `version: 3` is not decoration — mihomo picks the device
	// implementation off it (adapter/outbound/wireguard.go): ONLY the literal 3
	// selects amneziawg-go's v3 device, and every other value, an absent key
	// included, falls through to the legacy one. The legacy device ignores the v3
	// keys entirely, so emitting them without the version would leave the master
	// speaking 2.0 at an exit already brought up on 3.0 — a tunnel that never
	// handshakes. Hence: any 3.0 field at all forces version 3.
	//
	// Deliberately NOT emitted for a 2.0 param set: an explicit `version: 0` is
	// harmless to mihomo but would change every existing rendered config, and a
	// wireguard-proxy change forces a container restart fleet-wide (see
	// mihomo.ProxiesChanged) for no behaviour difference at all.
	if p.AWG3Enabled() {
		opt["version"] = 3
		for _, kv := range []struct{ key, value string }{
			{"header-protection-key", p.Shared.HeaderProtectionKey},
			{"content-padding-addition", p.Shared.ContentPaddingAddition},
			{"rekey-after-time", p.Shared.RekeyAfterTime},
			{"rekey-timeout", p.Shared.RekeyTimeout},
			{"reject-after-time", p.Shared.RejectAfterTime},
			{"keepalive-timeout", p.Shared.KeepaliveTimeout},
			{"max-handshake-attempts", p.Shared.MaxHandshakeAttempts},
		} {
			if kv.value != "" {
				opt[kv.key] = kv.value
			}
		}
	}
	return opt
}

// urlTestToleranceMS is the latency hysteresis for the url-test group: a better
// exit must beat the current one by more than this to trigger a switch. Tunnel
// round-trips are inherently high (full WG path to the probe — an earlier finding), so a
// generous tolerance prevents flapping between two similar exits.
const urlTestToleranceMS = 150

// groupOpts are the exit-selection knobs shared by every rendered group.
type groupOpts struct {
	balance        string
	healthInterval int
	maxFailedTimes int
}

// selectionGroup renders one exit-selection group. `balance` picks the mihomo
// group kind: url-test (lowest-latency member) and fallback (first healthy) are
// distinct types; everything else is a load-balance strategy.
func selectionGroup(name string, members []string, o groupOpts) map[string]any {
	g := map[string]any{
		"name":     name,
		"proxies":  toAnySlice(members),
		"url":      "http://cp.cloudflare.com/generate_204",
		"interval": o.healthInterval,
		"lazy":     false,
	}
	switch o.balance {
	case "url-test":
		g["type"] = "url-test"
		g["tolerance"] = urlTestToleranceMS
	case "fallback":
		g["type"] = "fallback"
	default:
		g["type"] = "load-balance"
		strategy := o.balance
		if strategy == "" {
			strategy = "round-robin"
		}
		g["strategy"] = strategy
	}
	if o.maxFailedTimes > 0 {
		g["max-failed-times"] = o.maxFailedTimes
	}
	return g
}

// wgBestGroups renders the master's exit selection as ONE flat group named
// wg-best over the members of the currently active tier (ADR-0029, revised).
//
// It used to emit a `fallback` group over two nested `load-balance` tier groups.
// That shape cannot make a TIER-level decision, verified against mihomo's source
// (2026-07-19) and matching upstream MetaCubeX/mihomo#2588, open and unanswered
// since 2026-02-28. Within a tier, consistent-hashing does rehash off a member
// already marked dead; what is broken is the parent's choice BETWEEN tiers:
//
//   - Fallback picks a member by AliveForTestUrl, and the only thing that ever
//     writes that flag on a nested GROUP is the parent's own URLTest.
//   - A URLTest against a load-balance group is a real dial through
//     LoadBalance.DialContext, which consistent-hashes on the *fixed test URL's*
//     host — so it deterministically probes ONE member forever. "Is the tier up"
//     silently degenerated into "is that one member up".
//   - Real client dial failures through the tier update only that tier group's
//     own private counters (GroupBase.onDialFailed); they never reach the parent's
//     decision. Live proof: a 48-minute outage with every primary member dead
//     logged "wg-primary failed multiple times" throughout while wg-best kept
//     reporting now=wg-primary and the healthy reserve tier took no traffic.
//
// The worst case is not a dead tier but a DECEIVED one: under RKN's volume-freeze
// a tiny HEAD probe still passes while real traffic dies, so no member is ever
// marked dead, nothing escalates, and clients hashed onto the broken exit stay
// broken indefinitely (observed live: pn8 answered the probe in 113ms while
// google/github/youtube/telegram were 0/16 through it).
//
// No combination of interval/url/expected-status/group-type fixes this; it is
// inherent to nesting a group inside a group. So tier SELECTION moves out of
// mihomo and into the master agent (reserveActive), which can weigh evidence a
// lightweight probe cannot see — throughput, multi-destination reachability — and
// mihomo is left with the one job it does correctly: balancing across a flat set
// of leaves whose liveness it checks individually.
//
// reserveActive picks which tier's members become wg-best's proxies. The inactive
// tier's tunnels stay rendered as proxies (existing connections survive) but leave
// the group, exactly like a drained exit. An empty chosen tier falls back to the
// other one, since mihomo rejects an empty group; RenderConfig refuses the
// both-empty case before this is reached (see the "all exits are drained" check).
//
// The group name is always wg-best, so routing rules never change and, with no
// reserve tier configured, the output stays byte-identical to the pre-ADR-0029
// config — load-bearing, because any drift rewrites config.yaml and forces a
// reload the fleet does not need.
func wgBestGroups(primary, reserve []string, o groupOpts, reserveActive bool) []any {
	members := primary
	if reserveActive && len(reserve) > 0 {
		members = reserve
	}
	if len(members) == 0 {
		// Chosen tier is empty: use whatever remains rather than emit an empty group.
		if members = primary; len(members) == 0 {
			members = reserve
		}
	}
	return []any{selectionGroup("wg-best", members, o)}
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
	// Ad/telemetry domains are blocked upstream by blocky, which answers NXDOMAIN.
	// Without a rule here they still fall through to MATCH: mihomo tries to resolve
	// the name, fails, and charges the failure to the GROUP —
	//   dial wg-best ... error: dns resolve failed: couldn't find ip
	//   because wg-best failed multiple times, activate health check
	// Measured live 2026-08-27: 37-69 health-check activations per hour on a fleet
	// whose exits were all healthy, driven entirely by telemetry hosts
	// (sessions.bugsnag.com, analytics.google.com, ...). Rejecting them here
	// attributes the failure to the rule instead, so a browser asking for ads can
	// no longer degrade the health of the group that carries every client.
	//
	// Emitted only alongside the other geo rules: GEOSITE needs the geosite
	// database, which is configured under the same condition.
	if len(spec.DirectGeo) > 0 {
		rules = append(rules, "GEOSITE,category-ads-all,REJECT")
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

// secretKeys are the config keys whose VALUE must never reach plan output.
// header-protection-key is one of them for the same reason as the other two: it
// is a chacha20 key whose whole purpose is that an observer does not have it.
var secretKeys = []string{"private-key:", "pre-shared-key:", "header-protection-key:"}

// RedactConfig masks secret key lines for plan output.
func RedactConfig(cfg string) string {
	var b strings.Builder
	for _, line := range strings.Split(cfg, "\n") {
		trimmed := strings.TrimSpace(line)
		if hasAnyPrefix(trimmed, secretKeys) {
			indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
			key := strings.SplitN(trimmed, ":", 2)[0]
			b.WriteString(indent + key + ": <redacted>\n")
			continue
		}
		b.WriteString(line + "\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// fallbackResolvers sit behind the fleet's own resolver so that losing it costs
// privacy rather than the data plane. Encrypted transports only: a master that has
// lost its resolver must degrade to "somebody else can see which names I ask for",
// never to "the country I am sitting in can read them off the wire". Quad9 and
// Cloudflare rather than the operator's own upstreams, which are a manifest concern
// and may themselves be unreachable in exactly this state.
var fallbackResolvers = []string{"tls://9.9.9.9", "tls://1.1.1.1"}

// listenAddr is the address mihomo binds its client-facing listeners on: the
// client gateway on the host, its own end of the veth inside the namespace.
func (in RenderInput) listenAddr() string {
	if in.NetnsPeerAddr != "" {
		return in.NetnsPeerAddr
	}
	return in.Spec.BindAddress
}

// controllerAddr is where the Clash API listens. Inside the namespace the
// management-overlay address does not exist, so the API moves to the veth with
// everything else — the agent reaches it over the link, which is the same path
// its own traffic takes.
//
// Losing this was not a cosmetic failure: the API is how the agent probes tier
// members, hot-reloads config, answers the mihomo-api health check and serves the
// dashboard. A mihomo that cannot bind it is a mihomo the master cannot steer.
func (in RenderInput) controllerAddr() string {
	ec := in.Spec.ExternalController
	if in.NetnsPeerAddr == "" || ec == "" {
		return ec
	}
	_, port, err := net.SplitHostPort(ec)
	if err != nil {
		return ec
	}
	return net.JoinHostPort(in.NetnsPeerAddr, port)
}
