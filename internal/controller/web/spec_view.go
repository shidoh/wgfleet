package web

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The node page's rendering of the controller's desired state.
//
// The shape follows what mature infrastructure consoles converged on (PatternFly /
// OpenShift, the Kubernetes dashboards, the cloud consoles), because the first two
// attempts here failed in exactly the way those conventions exist to prevent:
//
//   - A SUMMARY that answers "what does this node carry" in a handful of scalars.
//     No lists — a list in a summary is a second copy of some other page.
//   - DETAILS as grouped term/definition pairs, scalars only. Repeating entities
//     are never inlined here.
//   - TABLES for repeating entities, one per kind, and only for facts with no other
//     home. Per-exit liveness, latency and "who is carrying" live on the fleet page;
//     this page adds what that page lacks — endpoints with ports, tunnel addresses,
//     per-tunnel MTU.
//   - RAW, the complete spec as JSON. This is what makes curation-completeness a
//     non-goal: "I want to see everything" is answered by the manifest, not by an
//     ever-growing pile of hand-written sections. It is also why nothing here is
//     truncated to "first three and an ellipsis" — a partial list answers nothing,
//     and anything genuinely long belongs in the raw view.
//
// Every value is copied in by an ALLOWLIST. A NodeSpec reaches several credentials
// — the AWG 3.0 header-protection key on the interface and on every master↔exit
// tunnel, the WireGuard preshared key, REALITY UUIDs on both ends, end-user VLESS
// ids, and the free-form Custom overrides and files. The raw view is built from a
// redacted copy for the same reason. TestSpecViewLeaksNoCredentials plants a marker
// in every one of those fields and proves none reaches the page.

// redactedMark replaces a credential's value. Deliberately visible: the operator
// should learn that a value EXISTS without learning the value.
const redactedMark = "«redacted»"

// specRow is one term/definition pair. Hint is used sparingly — only where the
// value carries a consequence that is not obvious from reading it.
type specRow struct {
	Label string
	Value string
	Hint  string
	Badge string
}

// specGroup is a titled set of term/definition pairs about one subject. Note is a
// single line for the whole group — a caveat that applies to several of its rows
// belongs here, not repeated on each of them.
type specGroup struct {
	Title string
	Note  string
	Rows  []specRow
}

// specTable is one kind of repeating entity.
type specTable struct {
	Title string
	Note  string
	Head  []string
	Rows  [][]string
}

type specView struct {
	Summary []specRow
	Details []specGroup
	Tables  []specTable
	Raw     string
	RawErr  string
}

func buildSpecView(s domain.NodeSpec) specView {
	if s.Decommission {
		return specView{Summary: []specRow{{
			Label: "State",
			Value: "DECOMMISSION",
			Hint:  "the agent is tearing this node's data plane down; no desired state applies",
			Badge: "decommission",
		}}}
	}

	v := specView{Summary: summaryRows(s)}
	for _, g := range []specGroup{
		wgServerGroup(s), awgGroup(s), realityGroup(s.Reality), realityPortalGroup(s.Master), clientVLESSGroup(s.Master),
		lifelineGroup(s.Lifeline), routingGroup(s.Routing), dnsGroup(s.DNS), firewallGroup(s.Firewall),
		hardeningGroup(s), observabilityGroup(s),
	} {
		if len(g.Rows) > 0 {
			v.Details = append(v.Details, g)
		}
	}
	for _, t := range []specTable{exitProxiesTable(s.Master), peersTable(s.Peers)} {
		if len(t.Rows) > 0 {
			v.Tables = append(v.Tables, t)
		}
	}
	// JSON rather than YAML: the domain types carry no serialisation tags, so YAML
	// would mash the field names into "wgserver" / "listenport", while encoding/json
	// falls back to the exact Go names. Those names are the point — they are what an
	// operator greps for in the manifest reference and in the code.
	if raw, err := json.MarshalIndent(redactSpec(s), "", "  "); err != nil {
		v.RawErr = "cannot render the raw spec: " + err.Error()
	} else {
		v.Raw = string(raw)
	}
	return v
}

// --- summary -----------------------------------------------------------------

func summaryRows(s domain.NodeSpec) []specRow {
	var rows []specRow
	if r, ok := transportRow(s); ok {
		rows = append(rows, r)
	}
	if r, ok := mtuRow(s); ok {
		rows = append(rows, r)
	}
	if s.Role == domain.RoleExit {
		rows = append(rows, egressRow(s))
	}
	if r, ok := obfuscationRow(s); ok {
		rows = append(rows, r)
	}
	return rows
}

func transportRow(s domain.NodeSpec) (specRow, bool) {
	if s.Role == domain.RoleMaster {
		if s.Master == nil || len(s.Master.ExitTunnels) == 0 {
			return specRow{}, false
		}
		byTransport := map[string]int{}
		exits := map[string]bool{}
		for _, t := range s.Master.ExitTunnels {
			byTransport[string(t.Transport.OrDefault())]++
			exits[strings.TrimSuffix(t.Name, "-reality")] = true
		}
		// Says nothing about drain on purpose. ExitTunnel.Drained collapses two
		// different things — an operator draining a node, and the inactive half of a
		// dual-transport exit — and the spec cannot tell them apart. Reporting the raw
		// count read as "6 exits are out of service" when the truth was "6 proxies are
		// the transport nobody selected".
		return specRow{
			Label: "Exit proxies",
			Value: fmt.Sprintf("%d across %d exits — %s", len(s.Master.ExitTunnels), len(exits), countsByKey(byTransport)),
		}, true
	}

	enabled := s.Transports()
	if len(enabled) == 0 {
		return specRow{}, false
	}
	names := make([]string, 0, len(enabled))
	for _, t := range enabled {
		names = append(names, string(t))
	}
	active := string(s.ActiveTransport)
	if active == "" {
		active = string(enabled[0])
	}
	return specRow{Label: "Transport", Value: strings.Join(names, ", "), Badge: "active: " + active}, true
}

// mtuRow keeps the MTU chain in the summary because a wrong MTU is this project's
// most repeated production failure, and it black-holes full-size packets while
// pings and handshakes keep working — i.e. it looks healthy.
func mtuRow(s domain.NodeSpec) (specRow, bool) {
	var parts []string
	if s.WGServer.MTU > 0 {
		label := "clients"
		if s.Role == domain.RoleExit {
			label = "master↔exit"
		}
		parts = append(parts, fmt.Sprintf("%s %d", label, s.WGServer.MTU))
	}
	if s.Master != nil {
		seen := map[int]bool{}
		var tun []string
		for _, t := range s.Master.ExitTunnels {
			if t.MTU > 0 && !seen[t.MTU] {
				seen[t.MTU] = true
				tun = append(tun, fmt.Sprintf("%d", t.MTU))
			}
		}
		sort.Strings(tun)
		if len(tun) > 0 {
			parts = append(parts, "exit tunnels "+strings.Join(tun, "/"))
		}
	}
	r := specRow{Label: "MTU chain", Hint: "each tunnel layer subtracts; too high black-holes full-size packets while pings still work"}
	if s.WARPMTU > 0 {
		parts = append(parts, fmt.Sprintf("WARP %d", s.WARPMTU))
		r.Badge = "warp pinned"
	}
	if len(parts) == 0 {
		return specRow{}, false
	}
	r.Value = strings.Join(parts, " · ")
	return r, true
}

func egressRow(s domain.NodeSpec) specRow {
	r := specRow{Label: "Egress", Value: string(s.Egress)}
	if chain := s.EgressMethods(); len(chain) > 1 {
		names := make([]string, 0, len(chain))
		for _, m := range chain {
			names = append(names, string(m))
		}
		r.Value = strings.Join(names, " → ")
		r.Hint = "failover chain, tried left to right"
	}
	if s.EgressThroughputMinBps > 0 {
		r.Badge = "floor " + bitsPerSec(s.EgressThroughputMinBps)
	}
	return r
}

func obfuscationRow(s domain.NodeSpec) (specRow, bool) {
	awg := s.WGServer.AWG
	if awg == nil && s.Master != nil {
		for _, t := range s.Master.ExitTunnels {
			if t.AWG != nil {
				awg = t.AWG
				break
			}
		}
	}
	if awg == nil {
		return specRow{}, false
	}
	r := specRow{
		Label: "Obfuscation",
		Value: fmt.Sprintf("AmneziaWG · Jc=%d Jmin=%d Jmax=%d · S4=%d", awg.Local.Jc, awg.Local.Jmin, awg.Local.Jmax, awg.Shared.S4),
	}
	if awg.AWG3Enabled() {
		r.Badge = "AWG 3.0"
		r.Hint = "header protection and randomised timers are in force"
	}
	return r, true
}

// --- details (scalars only) ---------------------------------------------------

func wgServerGroup(s domain.NodeSpec) specGroup {
	w := s.WGServer
	if w.ListenPort == 0 && w.AddressPool == "" {
		return specGroup{}
	}
	g := specGroup{Title: "AWG server", Rows: []specRow{
		kv("Listen port", fmt.Sprintf("%d/udp", w.ListenPort)),
		kv("Address pool", w.AddressPool),
	}}
	if w.Address != "" {
		g.Rows = append(g.Rows, kv("Own address", w.Address))
	}
	g.Rows = append(g.Rows, kv("MTU", fmt.Sprintf("%d", w.MTU)))
	return g
}

func awgGroup(s domain.NodeSpec) specGroup {
	awg := s.WGServer.AWG
	if awg == nil {
		return specGroup{}
	}
	g := specGroup{
		Title: "AmneziaWG",
		Note:  "S and H must be identical on both ends of a tunnel; J and I are per-end.",
		Rows: []specRow{
			kv("S1-S4", fmt.Sprintf("%d / %d / %d / %d", awg.Shared.S1, awg.Shared.S2, awg.Shared.S3, awg.Shared.S4)),
			kv("H1-H4", fmt.Sprintf("%s, %s, %s, %s", awg.Shared.H1, awg.Shared.H2, awg.Shared.H3, awg.Shared.H4)),
			kv("Jc / Jmin / Jmax", fmt.Sprintf("%d / %d / %d", awg.Local.Jc, awg.Local.Jmin, awg.Local.Jmax)),
		},
	}
	if sig := joinNonEmptyValues(awg.Local.I1, awg.Local.I2, awg.Local.I3, awg.Local.I4, awg.Local.I5); sig != "" {
		g.Rows = append(g.Rows, kv("I1-I5", sig))
	}
	if l := s.WGServer.ClientAWGLocal; l != nil {
		g.Rows = append(g.Rows, kv("Client-side junk", fmt.Sprintf("Jc=%d Jmin=%d Jmax=%d", l.Jc, l.Jmin, l.Jmax)))
	}
	if awg.AWG3Enabled() {
		g.Rows = append(g.Rows, specRow{
			Label: "Header protection", Value: boolWord(awg.Shared.HeaderProtectionKey != "", "on", "off"),
			Hint: "needs S1-S4 ≥ 12 on both ends; the kernel accepts a violation silently",
		})
		// Only the timers that are actually set. Rendering the unset ones produced
		// four consecutive rows of "—", which is the same non-answer as a truncated
		// list: it costs the reader four lines to learn nothing.
		for _, kvp := range []struct{ label, value string }{
			{"Content padding", awg.Shared.ContentPaddingAddition},
			{"Rekey after", awg.Shared.RekeyAfterTime},
			{"Reject after", awg.Shared.RejectAfterTime},
			{"Keepalive", awg.Shared.KeepaliveTimeout},
		} {
			if kvp.value != "" {
				g.Rows = append(g.Rows, kv(kvp.label, kvp.value))
			}
		}
	}
	return g
}

func realityGroup(r *domain.RealityServerSpec) specGroup {
	if r == nil {
		return specGroup{}
	}
	if r.Bridge != nil {
		return realityBridgeGroup(r)
	}
	g := specGroup{
		Title: "REALITY inbound",
		Note:  "dest must support X25519MLKEM768, or the handshake fails with no error at all.",
		Rows: []specRow{
			kv("Listen port", fmt.Sprintf("%d/tcp", r.ListenPort)),
			kv("Camouflage", fmt.Sprintf("sni %s → dest %s", orDash(r.ServerName), orDash(r.Dest))),
			kv("Short ID", orDash(r.ShortID)),
		},
	}
	if r.XHTTPPath != "" || r.XHTTPMode != "" {
		g.Rows = append(g.Rows, kv("XHTTP", fmt.Sprintf("%s, mode %s", orDash(r.XHTTPPath), orDash(r.XHTTPMode))))
	}
	if rel := joinNonEmptyValues(boolWord(r.AllowEmptySNI, "empty SNI", ""), boolWord(r.AllowIPv6, "IPv6", "")); rel != "" {
		g.Rows = append(g.Rows, kv("Allowed", rel))
	}
	return g
}

// realityBridgeGroup renders an exit in the exit-initiated REALITY mode
// (ADR-0038): it listens on nothing and dials each master's portal.
func realityBridgeGroup(r *domain.RealityServerSpec) specGroup {
	g := specGroup{
		Title: "REALITY bridge (exit dials)",
		Note:  "no inbound and no open port: the exit dials each master's portal and the master sends streams back down it.",
	}
	if len(r.Bridge.Portals) == 0 {
		g.Rows = append(g.Rows, specRow{Label: "Dials", Value: "nothing",
			Hint: "no master is ready yet (wire 14, portal key, public IPv4); the controller log says which"})
	}
	for _, p := range r.Bridge.Portals {
		g.Rows = append(g.Rows, kv("Dials "+p.Master, fmt.Sprintf("%s, sni %s, fp %s", p.Address, orDash(p.ServerName), p.ResolvedFingerprint())))
	}
	if r.AllowIPv6 {
		g.Rows = append(g.Rows, kv("Allowed", "IPv6"))
	}
	return g
}

// realityPortalGroup renders a master's portal (ADR-0038): the inbound the
// bridges of exits in the exit-initiated mode dial.
func realityPortalGroup(m *domain.MasterSpec) specGroup {
	if m == nil || m.RealityPortal == nil {
		return specGroup{}
	}
	p := m.RealityPortal
	g := specGroup{
		Title: "REALITY portal",
		Note:  "exits in the exit-initiated mode dial this; mihomo reaches each of them through its SOCKS inbound.",
		Rows: []specRow{
			kv("Listen port", fmt.Sprintf("%d/tcp", p.ListenPort)),
			kv("Camouflage", fmt.Sprintf("sni %s → dest %s", orDash(p.ServerName), orDash(p.Dest))),
			kv("SOCKS port", fmt.Sprintf("%d", p.ResolvedSocksPort())),
		},
	}
	var exits []string
	for _, c := range p.Clients {
		exits = append(exits, c.Exit)
	}
	if len(exits) > 0 {
		g.Rows = append(g.Rows, specRow{Label: "Bridges from", Value: strings.Join(exits, ", "),
			Hint: "UUIDs are access credentials and are never rendered"})
	}
	return g
}

func clientVLESSGroup(m *domain.MasterSpec) specGroup {
	if m == nil || m.ClientVLESS == nil {
		return specGroup{}
	}
	c := m.ClientVLESS
	g := specGroup{
		Title: "Client VLESS inbound",
		Note:  "dest must support X25519MLKEM768, or the handshake fails with no error at all.",
		Rows: []specRow{
			kv("Listen port", fmt.Sprintf("%d/tcp", c.ListenPort)),
			kv("Camouflage", fmt.Sprintf("sni %s → dest %s", orDash(c.ServerName), orDash(c.Dest))),
		},
	}
	if c.XHTTPPath != "" || c.XHTTPMode != "" {
		g.Rows = append(g.Rows, kv("XHTTP", fmt.Sprintf("%s, mode %s", orDash(c.XHTTPPath), orDash(c.XHTTPMode))))
	}
	if names := clientNames(c.Clients); names != "" {
		g.Rows = append(g.Rows, specRow{Label: "Issued to", Value: names,
			Hint: "UUIDs are access credentials and are never rendered"})
	}
	return g
}

// lifelineGroup renders the exit's RESERVE client-facing interface — the door
// clients are handed when the master, the fleet's one publicly-dialed address,
// stops answering. It is the only part of an exit's desired state that has no
// other surface: the fleet page knows nothing about it, and its port, pool and
// egress are what an operator checks a reserve config against.
//
// The peers are a COUNT. They are the master's credentials projected onto this
// exit, they are listed in full on that master's clients page, and a second copy
// here would be the list-in-a-details this view exists to avoid.
func lifelineGroup(l *domain.LifelineSpec) specGroup {
	if l == nil {
		return specGroup{}
	}
	g := specGroup{
		Title: "Lifeline",
		Note:  "the reserve door: the master's own credentials, carried here, dialed directly when the master is unreachable.",
		Rows: []specRow{
			kv("Listen port", fmt.Sprintf("%d/udp", l.ListenPort)),
			kv("Address pool", orDash(l.AddressPool)),
			kv("Gateway", orDash(l.ServerAddress)),
			{Label: "Egress", Value: orDash(string(l.Egress)),
				Hint: "how this interface releases client traffic, independently of the exit's primary one"},
			kv("MTU", fmt.Sprintf("%d", l.MTU)),
			kv("DNS", orDash(strings.Join(l.DNS, ", "))),
			kv("Peers", fmt.Sprintf("%d", len(l.Clients))),
			kv("AllowedIPs", orDash(strings.Join(l.AllowedIPs, ", "))),
		},
	}
	return g
}

func routingGroup(r domain.RoutingSpec) specGroup {
	if r.EgressInterface == "" && len(r.DirectCIDRs) == 0 && r.ClientCIDR == "" {
		return specGroup{}
	}
	g := specGroup{Title: "Routing"}
	if r.EgressInterface != "" {
		g.Rows = append(g.Rows, kv("Egress interface", r.EgressInterface))
	}
	if r.ClientCIDR != "" {
		g.Rows = append(g.Rows, specRow{Label: "Client CIDR", Value: r.ClientCIDR,
			Hint: "the egress rule is scoped to this; unscoped it would send the host's own traffic into WARP"})
	}
	if len(r.DirectCIDRs) > 0 {
		g.Rows = append(g.Rows, kv("Direct networks", strings.Join(r.DirectCIDRs, ", ")))
	}
	if r.FwMark > 0 {
		g.Rows = append(g.Rows, kv("fwmark", fmt.Sprintf("%d", r.FwMark)))
	}
	return g
}

func dnsGroup(d domain.DNSFilterSpec) specGroup {
	if !d.Enabled {
		return specGroup{}
	}
	g := specGroup{Title: "DNS filter", Rows: []specRow{kv("Bind", orDash(d.MgmtAddr))}}
	if d.ClientBindAddr != "" {
		g.Rows = append(g.Rows, kv("Client bind", d.ClientBindAddr))
	}
	if len(d.Upstreams) > 0 {
		g.Rows = append(g.Rows, kv("Upstreams", strings.Join(d.Upstreams, ", ")))
	}
	if len(d.Allowlist) > 0 {
		g.Rows = append(g.Rows, kv("Allowlist", strings.Join(d.Allowlist, ", ")))
	}
	if len(d.Custom.Overrides) > 0 {
		g.Rows = append(g.Rows, specRow{Label: "Operator overrides", Value: strings.Join(sortedKeys(d.Custom.Overrides), ", "),
			Hint: "keys only — override values are free-form and may carry secrets"})
	}
	return g
}

func firewallGroup(f domain.FirewallSpec) specGroup {
	g := specGroup{Title: "Firewall", Rows: []specRow{
		{Label: "AS blacklist", Value: boolWord(f.ASBlacklist, "on", "off"),
			Hint: "drops known scanner ASNs before they reach the data plane"},
	}}
	if f.WGPort > 0 {
		g.Rows = append(g.Rows, kv("AWG port", fmt.Sprintf("%d/udp", f.WGPort)))
	}
	if f.RealityPort > 0 {
		g.Rows = append(g.Rows, kv("REALITY port", fmt.Sprintf("%d/tcp", f.RealityPort)))
	}
	if len(f.PublicTCPPorts) > 0 {
		g.Rows = append(g.Rows, kv("Open TCP", intsCSV(f.PublicTCPPorts)))
	}
	if len(f.PublicUDPPorts) > 0 {
		g.Rows = append(g.Rows, kv("Open UDP", intsCSV(f.PublicUDPPorts)))
	}
	if len(f.Whitelist) > 0 {
		g.Rows = append(g.Rows, kv("Whitelist", strings.Join(f.Whitelist, ", ")))
	}
	return g
}

// hardeningGroup is one row, not two. Both values are booleans an operator sets
// once and then never reads; giving each its own line spent two of the page's
// scarcest resource — vertical rows — on almost nothing.
func hardeningGroup(s domain.NodeSpec) specGroup {
	r := specRow{Label: "Host hardening", Value: fmt.Sprintf("sshd drop-in %s · fail2ban %s",
		boolWord(s.SSHDHardeningEnabled(), "on", "off"), boolWord(s.Fail2banEnabled(), "on", "off"))}
	if !s.SSHDHardeningEnabled() || !s.Fail2banEnabled() {
		r.Badge = "opted out"
	}
	return specGroup{Title: "Host", Rows: []specRow{r}}
}

func observabilityGroup(s domain.NodeSpec) specGroup {
	g := specGroup{Title: "Observability"}
	if e := joinNonEmptyValues(
		boolWord(s.Exporters.Node, "node", ""),
		boolWord(s.Exporters.WG, "wireguard", ""),
		boolWord(s.Exporters.WARP, "warp", "")); e != "" {
		g.Rows = append(g.Rows, kv("Exporters", e))
	}
	if s.EgressThroughputMinBps > 0 {
		g.Rows = append(g.Rows, specRow{Label: "Egress throughput floor", Value: bitsPerSec(s.EgressThroughputMinBps),
			Hint: "below this the egress reads as degraded and failover may fire"})
	}
	if s.EgressThroughputProbeURL != "" {
		g.Rows = append(g.Rows, kv("Throughput probe", s.EgressThroughputProbeURL))
	}
	return g
}

// --- tables -------------------------------------------------------------------

// exitProxiesTable carries the master↔exit facts nothing else shows: the endpoint
// WITH its port, the tunnel address and the per-tunnel MTU. Liveness, latency and
// which exit currently carries traffic belong to the fleet page and are not
// repeated. Neither the preshared key nor a REALITY tunnel UUID appears.
func exitProxiesTable(m *domain.MasterSpec) specTable {
	if m == nil || len(m.ExitTunnels) == 0 {
		return specTable{}
	}
	t := specTable{
		Title: "Exit proxies",
		Note:  "endpoints and MTU per proxy; liveness and the carrying exit are on the fleet page.",
		Head:  []string{"Proxy", "Transport", "Endpoint", "Tunnel IP", "MTU", "Tier"},
	}
	for _, e := range m.ExitTunnels {
		tier := "primary"
		if e.Reserve {
			tier = "reserve"
		}
		endpoint := orDash(e.Endpoint)
		if e.Reality != nil && e.Reality.Reverse {
			endpoint = "via portal (exit dials)"
		}
		t.Rows = append(t.Rows, []string{
			e.Name, string(e.Transport.OrDefault()), endpoint,
			orDash(e.TunnelIP), fmt.Sprintf("%d", e.MTU), tier,
		})
	}
	return t
}

func peersTable(peers []domain.PeerSpec) specTable {
	if len(peers) == 0 {
		return specTable{}
	}
	t := specTable{Title: "Peers", Head: []string{"Peer", "Allowed IPs", "Endpoint", "Keepalive"}}
	for _, p := range peers {
		ep := p.Endpoint
		if ep == "" {
			ep = "dials in"
		}
		ka := "—"
		if p.Keepalive > 0 {
			ka = fmt.Sprintf("%ds", p.Keepalive)
		}
		t.Rows = append(t.Rows, []string{orDash(p.Name), strings.Join(p.AllowedIPs, ", "), ep, ka})
	}
	return t
}

// --- raw ----------------------------------------------------------------------

// redactSpec returns a copy of s with every credential replaced. It copies each
// pointed-to struct and slice it touches, so the caller's spec is never mutated —
// the same spec object also feeds the wg-easy and mihomo links on this page.
func redactSpec(s domain.NodeSpec) domain.NodeSpec {
	if s.WGServer.AWG != nil {
		awg := *s.WGServer.AWG
		awg.Shared.HeaderProtectionKey = redactIfSet(awg.Shared.HeaderProtectionKey)
		s.WGServer.AWG = &awg
	}
	if s.Reality != nil {
		r := *s.Reality
		r.UUID = redactIfSet(r.UUID)
		if r.Bridge != nil {
			b := *r.Bridge
			ps := append([]domain.RealityPortalPeer(nil), b.Portals...)
			for i := range ps {
				ps[i].UUID = redactIfSet(ps[i].UUID)
			}
			b.Portals = ps
			r.Bridge = &b
		}
		s.Reality = &r
	}
	if s.Master != nil {
		m := *s.Master
		tunnels := append([]domain.ExitTunnel(nil), m.ExitTunnels...)
		for i := range tunnels {
			tunnels[i].PresharedKey = redactIfSet(tunnels[i].PresharedKey)
			if tunnels[i].AWG != nil {
				a := *tunnels[i].AWG
				a.Shared.HeaderProtectionKey = redactIfSet(a.Shared.HeaderProtectionKey)
				tunnels[i].AWG = &a
			}
			if tunnels[i].Reality != nil {
				rt := *tunnels[i].Reality
				rt.UUID = redactIfSet(rt.UUID)
				tunnels[i].Reality = &rt
			}
		}
		m.ExitTunnels = tunnels
		if m.RealityPortal != nil {
			rp := *m.RealityPortal
			cs := append([]domain.RealityPortalClient(nil), rp.Clients...)
			for i := range cs {
				cs[i].UUID = redactIfSet(cs[i].UUID)
			}
			rp.Clients = cs
			m.RealityPortal = &rp
		}
		if m.ClientVLESS != nil {
			cv := *m.ClientVLESS
			cs := append([]domain.VLESSClient(nil), cv.Clients...)
			for i := range cs {
				cs[i].UUID = redactIfSet(cs[i].UUID)
			}
			cv.Clients = cs
			m.ClientVLESS = &cv
		}
		if m.ClientWG != nil {
			cw := *m.ClientWG
			// Both halves are secret and both were reaching the page: every end
			// user's preshared key, and the client interface's own header-protection
			// key — the one value redacted for WGServer and every exit tunnel above.
			if cw.AWG != nil {
				a := *cw.AWG
				a.Shared.HeaderProtectionKey = redactIfSet(a.Shared.HeaderProtectionKey)
				cw.AWG = &a
			}
			peers := append([]domain.WGClientPeer(nil), cw.Clients...)
			for i := range peers {
				peers[i].PresharedKey = redactIfSet(peers[i].PresharedKey)
			}
			cw.Clients = peers
			m.ClientWG = &cw
		}
		m.Custom = redactCustom(m.Custom)
		s.Master = &m
	}
	if s.Lifeline != nil {
		// The reserve interface carries the SAME end-user secrets as the master's
		// client interface — every credential's preshared key (derived per exit, but
		// a key nonetheless) and its own header-protection key. It is a second copy
		// of the field the block above redacts, and it reached the raw view untouched.
		l := *s.Lifeline
		if l.AWG != nil {
			a := *l.AWG
			a.Shared.HeaderProtectionKey = redactIfSet(a.Shared.HeaderProtectionKey)
			l.AWG = &a
		}
		peers := append([]domain.WGClientPeer(nil), l.Clients...)
		for i := range peers {
			peers[i].PresharedKey = redactIfSet(peers[i].PresharedKey)
		}
		l.Clients = peers
		s.Lifeline = &l
	}
	s.DNS.Custom = redactCustom(s.DNS.Custom)
	return s
}

// redactCustom keeps the KEYS of an operator override map and the PATHS of extra
// files — those say what was customised, which is the useful part — and replaces
// every value and file body. Values are free-form (`any`, nested arbitrarily deep)
// and demonstrably carry secrets: the mihomo Clash API secret lives in exactly this
// map. Nothing that cannot be allowlisted gets rendered.
func redactCustom(c domain.CustomConfig) domain.CustomConfig {
	if len(c.Overrides) > 0 {
		out := make(map[string]any, len(c.Overrides))
		for k := range c.Overrides {
			out[k] = redactedMark
		}
		c.Overrides = out
	}
	if len(c.Files) > 0 {
		files := append([]domain.ManagedFile(nil), c.Files...)
		for i := range files {
			files[i].Content = redactedMark
		}
		c.Files = files
	}
	return c
}

func redactIfSet(v string) string {
	if v == "" {
		return ""
	}
	return redactedMark
}

// --- helpers ------------------------------------------------------------------

func kv(label, value string) specRow { return specRow{Label: label, Value: value} }

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func boolWord(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func joinNonEmptyValues(vals ...string) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, ", ")
}

func intsCSV(vals []int) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, fmt.Sprintf("%d", v))
	}
	return strings.Join(out, ", ")
}

func countsByKey(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%d %s", m[k], k))
	}
	return strings.Join(out, ", ")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// clientNames lists operator-facing labels only; UUIDs and short-ids stay out.
func clientNames(cs []domain.VLESSClient) string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		if c.Name != "" {
			names = append(names, c.Name)
		}
	}
	return strings.Join(names, ", ")
}

func bitsPerSec(bps int) string {
	switch {
	case bps >= 1_000_000:
		return fmt.Sprintf("%.1f Mbit/s", float64(bps)/1_000_000)
	case bps >= 1_000:
		return fmt.Sprintf("%.0f kbit/s", float64(bps)/1_000)
	default:
		return fmt.Sprintf("%d bit/s", bps)
	}
}
