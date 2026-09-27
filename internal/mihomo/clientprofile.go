package mihomo

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// The CLIENT profile: what a mihomo app (FlClash, ClashMetaForAndroid, ClashX
// Meta, Clash Verge Rev) fetches from the portal for one device (ADR-0035). It
// lives beside the master's renderer because it must reuse the same AmneziaWG
// option block — the master↔exit leg already speaks `version: 3` through
// awgOption, and a second spelling of those keys is a second place to be wrong.

const (
	ClientProfileAutoGroup      = "auto"
	ClientProfileSelectGroup    = "wgfleet"
	ClientProfileHealthURL      = "http://www.gstatic.com/generate_204"
	ClientProfileHealthInterval = 300
)

// isReservedProfileName reports whether name collides with a group this profile
// already defines for itself, or with a mihomo built-in policy used verbatim as a
// rule target elsewhere in the same document (clientRules).
func isReservedProfileName(name string) bool {
	switch name {
	case ClientProfileAutoGroup, ClientProfileSelectGroup, "DIRECT", "REJECT":
		return true
	default:
		return false
	}
}

// clientPrivateRanges go DIRECT so the device's own LAN keeps working with the
// tunnel up. Everything that must reach the tunnel and happens to be RFC1918 —
// the portal on the mgmt overlay, a master's client pool, route_through_cidrs —
// is matched BEFORE these.
var clientPrivateRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8"}

// clientBootstrapResolvers resolve the proxy servers' own names (an endpoint may
// be a DNS name) and nothing else. They cannot be blocky: that is reached
// THROUGH a proxy, which cannot be dialled before its server resolves.
var clientBootstrapResolvers = []string{"77.88.8.8", "1.1.1.1"}

// ClientDNSMode is fake-ip for one reason outside mihomo: Clash Verge Rev on
// macOS points the system resolver at a public address — the only way the OS
// resolver's queries enter the tun — ONLY under fake-ip (its enhance/tun.rs).
// Under redir-host a resolver the router handed out over DHCP stays in place;
// its LAN route never enters the tun, so every name the OS looks up leaves
// beside the tunnel. Measured 2026-09-27 on the mihomo debug log. The profile
// cannot tell which app fetched it; fake-ip is the others' usual mode anyway.
const ClientDNSMode = "fake-ip"

// ClientFakeIPFilter: names of whatever network the device sits on get a real
// answer rather than a fake address. The fleet resolver cannot know them, so
// they fail fast with NXDOMAIN instead of as a connection into the tunnel.
var ClientFakeIPFilter = []string{"+.lan", "+.local", "+.home.arpa"}

// ClientProfileMaster is one master's share of a device's profile. AWG is the
// very input the .conf renders from — not a copy of its fields — so the two
// cannot disagree about anything but spelling.
type ClientProfileMaster struct {
	Name         string
	AWG          *wg.ClientConfigInput
	VLESS        *domain.ClientVLESSEndpoint
	RouteThrough []string
	DNS          []string
	ClientPool   string
}

// ClientProfileInput is a whole device: its masters in manifest order, plus the
// fleet's management overlay.
type ClientProfileInput struct {
	Masters   []ClientProfileMaster
	MgmtCIDRs []string
}

// ClientNameserver is how every client config the controller hands out names a
// fleet resolver: TCP :53, dialled through `via`. Not DoT (:853): the master
// admits :853 only from mihomo's namespace, while on the client interface it
// opens the resolver port alone (internal/netfw, ClientDNSPort) — DoT over the
// AWG leg would be dropped. TCP rather than UDP so it rides a VLESS proxy too.
func ClientNameserver(addr, via string) string {
	return "tcp://" + net.JoinHostPort(addr, "53") + "#" + via
}

// RenderClientProfile renders one device's mihomo profile.
func RenderClientProfile(in ClientProfileInput) (string, error) {
	var (
		proxies, groups []any
		all             []string
		pools           []string
		nameservers     []string
	)
	through := append([]string(nil), in.MgmtCIDRs...)
	for _, m := range in.Masters {
		if strings.ContainsAny(m.Name, ",#") {
			return "", fmt.Errorf("client profile: master name %q contains ',' or '#', which mihomo reads as syntax", m.Name)
		}
		// A master's OWN fallback group is named after it (below); reusing one of the
		// two names this function already reserves for the fleet-wide groups, or one
		// of mihomo's built-in policies, would collide with the group or the policy
		// rather than merely look like it.
		if isReservedProfileName(m.Name) {
			return "", fmt.Errorf("client profile: master name %q is reserved (mihomo group/policy name)", m.Name)
		}
		var own []string
		if m.AWG != nil {
			p, err := clientWireguardProxy(m.Name+"-awg", *m.AWG)
			if err != nil {
				return "", fmt.Errorf("client profile: master %q: %w", m.Name, err)
			}
			proxies, own = append(proxies, p), append(own, m.Name+"-awg")
		}
		if m.VLESS != nil {
			proxies, own = append(proxies, clientVLESSProxy(m.Name+"-vless", *m.VLESS)), append(own, m.Name+"-vless")
		}
		if len(own) == 0 {
			continue
		}
		all = append(all, own...)
		// The master's own group: its resolver and its client pool are reachable
		// through ITS proxies only, whichever one is alive.
		groups = append(groups, fallbackGroup(m.Name, own))
		through = append(through, m.RouteThrough...)
		if m.ClientPool != "" {
			pools = append(pools, "IP-CIDR,"+m.ClientPool+","+m.Name)
		}
		for _, d := range m.DNS {
			nameservers = append(nameservers, ClientNameserver(d, m.Name))
		}
	}
	if len(proxies) == 0 {
		return "", errors.New("client profile: no proxy to render")
	}
	groups = append(groups,
		fallbackGroup(ClientProfileAutoGroup, all),
		map[string]any{
			// fallback catches a DEAD proxy only; this is for the one it cannot see —
			// AWG alive but throttled — where the person picks VLESS by hand.
			"name":    ClientProfileSelectGroup,
			"type":    "select",
			"proxies": toAnySlice(append([]string{ClientProfileAutoGroup}, all...)),
		})

	doc := map[string]any{
		"mode":      "rule",
		"log-level": "info",
		// The data plane is IPv4-only.
		"ipv6":         false,
		"proxies":      proxies,
		"proxy-groups": groups,
		"rules":        clientRules(dedupe(through), pools),
	}
	if len(nameservers) > 0 {
		doc["dns"] = map[string]any{
			"enable":                  true,
			"ipv6":                    false,
			"enhanced-mode":           ClientDNSMode,
			"fake-ip-filter":          toAnySlice(ClientFakeIPFilter),
			"default-nameserver":      toAnySlice(clientBootstrapResolvers),
			"proxy-server-nameserver": toAnySlice(clientBootstrapResolvers),
			// Queried in parallel, first answer wins: a dead master's resolver costs
			// a timeout on a race nobody waits for.
			"nameserver": toAnySlice(dedupe(nameservers)),
		}
	}
	return marshalYAML(doc)
}

func fallbackGroup(name string, members []string) map[string]any {
	return map[string]any{
		"name":     name,
		"type":     "fallback",
		"proxies":  toAnySlice(members),
		"url":      ClientProfileHealthURL,
		"interval": ClientProfileHealthInterval,
	}
}

// clientRules: internal nets and the mgmt overlay through the tunnel, each
// master's pool through that master, the device's own LAN direct, the rest to
// the master — which does the geo split itself. No no-resolve: under fake-ip the
// app hands mihomo a name, and an IP rule that skips names would send a work
// host resolving to 10.x past its route-through rule to MATCH.
func clientRules(through, pools []string) []any {
	var rules []string
	for _, c := range through {
		rules = append(rules, "IP-CIDR,"+c+","+ClientProfileSelectGroup)
	}
	rules = append(rules, pools...)
	for _, c := range clientPrivateRanges {
		rules = append(rules, "IP-CIDR,"+c+",DIRECT")
	}
	rules = append(rules, "MATCH,"+ClientProfileSelectGroup)
	return toAnySlice(rules)
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// clientWireguardProxy renders the AWG proxy from the .conf's own input. Same
// shape as the master↔exit wireguardProxy (peers list, proxy-level keepalive —
// mihomo drops a peer-level one, an earlier finding), same awgOption.
func clientWireguardProxy(name string, in wg.ClientConfigInput) (map[string]any, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	host, port, err := splitEndpoint(in.Endpoint)
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParsePrefix(in.Client.Address)
	if err != nil {
		return nil, fmt.Errorf("client %q address %q: %w", in.Client.Name, in.Client.Address, err)
	}
	allowed := in.Spec.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}
	peer := map[string]any{
		"server":      host,
		"port":        port,
		"public-key":  in.ServerPublicKey,
		"allowed-ips": toAnySlice(allowed),
	}
	if in.Client.PresharedKey != "" {
		peer["pre-shared-key"] = in.Client.PresharedKey
	}
	proxy := map[string]any{
		"name":        name,
		"type":        "wireguard",
		"ip":          addr.Addr().String(),
		"private-key": in.Client.PrivateKey,
		"udp":         true,
		// mihomo takes an integer only; this is what the .conf prints.
		"persistent-keepalive": wg.ClientKeepaliveFor(in.Spec.Keepalive, in.Client.ID),
		"peers":                []any{peer},
	}
	v6, err := wg.ClientTunnelV6(in.Spec, in.Client.Address)
	if err != nil {
		return nil, err
	}
	if v6 != "" {
		proxy["ipv6"] = strings.TrimSuffix(v6, "/128")
	}
	if in.Spec.MTU > 0 {
		proxy["mtu"] = in.Spec.MTU
	}
	params, err := wg.ClientAWGParams(in.Spec, in.Client)
	if err != nil {
		return nil, err
	}
	if params != nil {
		// version: 3 appears exactly when the credential's mode (client_awg.awg3)
		// put 3.x fields into the spec — nothing here enables it.
		proxy["amnezia-wg-option"] = awgOption(*params)
	}
	return proxy, nil
}

// clientVLESSProxy renders the REALITY proxy from the one VLESS derivation; the
// transport shape mirrors the master's realityProxy.
func clientVLESSProxy(name string, e domain.ClientVLESSEndpoint) map[string]any {
	proxy := map[string]any{
		"name":       name,
		"type":       "vless",
		"server":     e.Host,
		"port":       e.Port,
		"uuid":       e.UUID,
		"tls":        true,
		"udp":        true,
		"servername": e.MihomoServerName(),
		"reality-opts": map[string]any{
			"public-key": e.PublicKey,
			"short-id":   e.ShortID,
		},
	}
	if e.Fingerprint != "" {
		proxy["client-fingerprint"] = e.Fingerprint
	}
	if e.Vision {
		proxy["network"] = "tcp"
		proxy["flow"] = "xtls-rprx-vision"
		return proxy
	}
	xhttp := map[string]any{"path": e.XHTTPPath, "mode": e.XHTTPMode}
	if e.Mux {
		xhttp["reuse-settings"] = map[string]any{
			"max-concurrency":     domain.ClientVLESSXMUXMaxConcurrency,
			"h-max-request-times": domain.ClientVLESSXMUXHMaxRequestTimes,
			"h-max-reusable-secs": domain.ClientVLESSXMUXHMaxReusableSecs,
		}
	}
	proxy["network"] = "xhttp"
	proxy["xhttp-opts"] = xhttp
	return proxy
}
