package web

import (
	"fmt"
	"sort"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// The node page's rendering of the controller's desired state.
//
// This replaced a single pre-formatted text blob. The blob dumped every field it
// knew about in one undifferentiated column, which made the page unreadable AND —
// less obviously — incomplete: six NodeSpec fields were never rendered at all,
// including EnabledTransports and ActiveTransport. On a fleet where most exits run
// reality-xhttp, the page could not tell you which transport a node was on.
//
// Two things drive the shape here:
//
//   - A typed view instead of a string. The template does the layout, so the page
//     can have structure; and the tests can assert on facts ("the active transport
//     is present", "no credential is") instead of grepping formatted text.
//   - ALLOWLIST, never denylist. Every value below is copied in deliberately. A
//     NodeSpec reaches several credentials — the AWG 3.0 header-protection key on
//     the interface and on every master↔exit tunnel, the WireGuard preshared key,
//     REALITY UUIDs on both ends, end-user VLESS ids, and the free-form
//     Custom.Overrides maps that carry the mihomo Clash API secret. A field added
//     to the domain later is therefore invisible here until someone opts it in,
//     which is the only safe default for something rendered into a browser.
//     TestSpecViewLeaksNoCredentials plants a marker in every one of those fields
//     and proves none reaches the page.

// specRow is one label/value line. Hint is muted secondary text (why the value
// matters); Badge is a short emphasis marker (pinned, drained, off).
type specRow struct {
	Label string
	Value string
	Hint  string
	Badge string
}

// specSection is a foldable group of detail rows.
type specSection struct {
	Title string
	Note  string
	Rows  []specRow
}

// specView is what the template renders: an always-visible summary card plus the
// detail sections beneath it.
type specView struct {
	Summary  []specRow
	Sections []specSection
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
	v.Sections = appendSection(v.Sections, wgServerSection(s))
	v.Sections = appendSection(v.Sections, obfuscationSection(s))
	v.Sections = appendSection(v.Sections, peersSection(s.Peers))
	v.Sections = appendSection(v.Sections, exitTunnelsSection(s.Master))
	v.Sections = appendSection(v.Sections, clientVLESSSection(s.Master))
	v.Sections = appendSection(v.Sections, realitySection(s.Reality))
	v.Sections = appendSection(v.Sections, routingSection(s.Routing))
	v.Sections = appendSection(v.Sections, dnsSection(s.DNS))
	v.Sections = appendSection(v.Sections, firewallSection(s.Firewall))
	v.Sections = appendSection(v.Sections, hardeningSection(s))
	v.Sections = appendSection(v.Sections, exportersSection(s))
	return v
}

// summaryRows is the always-visible card: what this node carries, in the order an
// operator asks it. Transport first because on a dual-transport fleet it is the
// question; MTU second because a wrong MTU is this project's most repeated
// production failure and it used to be buried three levels down.
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

// transportRow answers "what is this node speaking right now". For an exit that is
// its enabled set plus the ACTIVE one (the knob the operator flips); for a master
// it is the split of its exit proxies across transports.
func transportRow(s domain.NodeSpec) (specRow, bool) {
	if s.Role == domain.RoleMaster {
		if s.Master == nil || len(s.Master.ExitTunnels) == 0 {
			return specRow{}, false
		}
		byTransport := map[string]int{}
		drained := 0
		for _, t := range s.Master.ExitTunnels {
			byTransport[string(t.Transport.OrDefault())]++
			if t.Drained {
				drained++
			}
		}
		row := specRow{
			Label: "Transport",
			Value: fmt.Sprintf("%d exit proxies (%s)", len(s.Master.ExitTunnels), countsByKey(byTransport)),
			Hint:  "mihomo dials these; a drained exit stays configured but takes no new traffic",
		}
		if drained > 0 {
			row.Badge = fmt.Sprintf("%d drained", drained)
		}
		return row, true
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
	return specRow{
		Label: "Transport",
		Value: fmt.Sprintf("%s — ACTIVE: %s", strings.Join(names, ", "), active),
		Hint:  "the active transport is the one the master routes client traffic through",
		Badge: active,
	}, true
}

// mtuRow renders the MTU chain on one line. Every layer subtracts, and getting it
// wrong black-holes full-size packets while pings and handshakes keep working —
// which is why it belongs in the summary and not in a fold.
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
		if len(tun) > 0 {
			parts = append(parts, "exit tunnels "+strings.Join(tun, "/"))
		}
	}
	row := specRow{Label: "MTU chain", Hint: "each tunnel layer subtracts; too high black-holes full-size packets while pings still work"}
	if s.WARPMTU > 0 {
		parts = append(parts, fmt.Sprintf("WARP %d", s.WARPMTU))
		row.Badge = "warp pinned"
	}
	if len(parts) == 0 {
		return specRow{}, false
	}
	row.Value = strings.Join(parts, " · ")
	return row, true
}

func egressRow(s domain.NodeSpec) specRow {
	row := specRow{Label: "Egress", Value: string(s.Egress),
		Hint: "how this exit reaches the internet"}
	if chain := s.EgressMethods(); len(chain) > 1 {
		names := make([]string, 0, len(chain))
		for _, m := range chain {
			names = append(names, string(m))
		}
		row.Value = strings.Join(names, " → ")
		row.Hint = "failover chain, tried left to right"
	}
	if s.EgressThroughputMinBps > 0 {
		row.Badge = fmt.Sprintf("floor %s", bitsPerSec(s.EgressThroughputMinBps))
	}
	return row
}

// obfuscationRow is a one-line fingerprint, not the parameter dump. The full
// S/H/I values live in their own section for when someone is comparing two ends.
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
	row := specRow{
		Label: "Obfuscation",
		Value: fmt.Sprintf("AmneziaWG · Jc=%d Jmin=%d Jmax=%d · S4=%d", awg.Local.Jc, awg.Local.Jmin, awg.Local.Jmax, awg.Shared.S4),
		Hint:  "S and H must match on both ends of a tunnel; Jc/Jmin/Jmax and I1-I5 are per-end",
	}
	if awg.AWG3Enabled() {
		row.Badge = "AWG 3.0"
		row.Hint = "AmneziaWG 3.0: header protection and randomised timers are in force"
	}
	return row, true
}

func wgServerSection(s domain.NodeSpec) specSection {
	w := s.WGServer
	if w.ListenPort == 0 && w.AddressPool == "" {
		return specSection{}
	}
	sec := specSection{Title: "WireGuard server"}
	sec.Rows = append(sec.Rows,
		row("Listen port", fmt.Sprintf("%d/udp", w.ListenPort), ""),
		row("Address pool", w.AddressPool, ""),
	)
	if w.Address != "" {
		sec.Rows = append(sec.Rows, row("Own address", w.Address, ""))
	}
	sec.Rows = append(sec.Rows, row("MTU", fmt.Sprintf("%d", w.MTU), ""))
	return sec
}

// obfuscationSection carries the values an operator compares across a tunnel.
// The AWG 3.0 header-protection key is deliberately NOT among them: it is a
// shared chacha20 secret, and its presence is reported as a yes/no instead.
func obfuscationSection(s domain.NodeSpec) specSection {
	awg := s.WGServer.AWG
	if awg == nil {
		return specSection{}
	}
	sec := specSection{
		Title: "AmneziaWG parameters",
		Note:  "S1-S4 and H1-H4 must be identical on both ends; Jc/Jmin/Jmax and I1-I5 may differ per end.",
	}
	sec.Rows = append(sec.Rows,
		row("S1-S4", fmt.Sprintf("%d / %d / %d / %d", awg.Shared.S1, awg.Shared.S2, awg.Shared.S3, awg.Shared.S4), "junk prefix sizes (shared)"),
		row("H1-H4", fmt.Sprintf("%s, %s, %s, %s", awg.Shared.H1, awg.Shared.H2, awg.Shared.H3, awg.Shared.H4), "header type ranges (shared)"),
		row("Jc / Jmin / Jmax", fmt.Sprintf("%d / %d / %d", awg.Local.Jc, awg.Local.Jmin, awg.Local.Jmax), "junk packets (per-end)"),
	)
	if sig := joinNonEmptyValues(awg.Local.I1, awg.Local.I2, awg.Local.I3, awg.Local.I4, awg.Local.I5); sig != "" {
		sec.Rows = append(sec.Rows, row("I1-I5", sig, "signature packets (per-end)"))
	}
	if l := s.WGServer.ClientAWGLocal; l != nil {
		sec.Rows = append(sec.Rows, row("Client-side junk",
			fmt.Sprintf("Jc=%d Jmin=%d Jmax=%d", l.Jc, l.Jmin, l.Jmax),
			"clients emit their own decoy, distinct from this interface's"))
	}
	if awg.AWG3Enabled() {
		sec.Rows = append(sec.Rows,
			row("Header protection", boolWord(awg.Shared.HeaderProtectionKey != "", "on (key not shown)", "off"),
				"AWG 3.0; requires S1-S4 >= 12 on both ends"),
			row("Content padding", orDash(awg.Shared.ContentPaddingAddition), "AWG 3.0, per data packet"),
			row("Rekey after", orDash(awg.Shared.RekeyAfterTime), "AWG 3.0 randomised timer"),
			row("Reject after", orDash(awg.Shared.RejectAfterTime), "AWG 3.0 randomised timer"),
			row("Keepalive", orDash(awg.Shared.KeepaliveTimeout), "AWG 3.0 randomised timer"),
		)
	}
	return sec
}

func peersSection(peers []domain.PeerSpec) specSection {
	if len(peers) == 0 {
		return specSection{}
	}
	sec := specSection{Title: fmt.Sprintf("Peers (%d)", len(peers))}
	for _, p := range peers {
		v := strings.Join(p.AllowedIPs, ", ")
		hint := "dials in (no endpoint)"
		if p.Endpoint != "" {
			hint = "endpoint " + p.Endpoint
		}
		if p.Keepalive > 0 {
			hint += fmt.Sprintf(" · keepalive %ds", p.Keepalive)
		}
		sec.Rows = append(sec.Rows, row(orDash(p.Name), v, hint))
	}
	return sec
}

// exitTunnelsSection lists the master's proxies. Neither the preshared key nor a
// REALITY tunnel UUID appears — both are credentials.
func exitTunnelsSection(m *domain.MasterSpec) specSection {
	if m == nil || len(m.ExitTunnels) == 0 {
		return specSection{}
	}
	sec := specSection{
		Title: fmt.Sprintf("Exit proxies (%d)", len(m.ExitTunnels)),
		Note:  "one mihomo proxy per exit; a drained exit stays configured so existing connections survive but takes no new traffic.",
	}
	for _, t := range m.ExitTunnels {
		hint := fmt.Sprintf("%s · tunnel ip %s · mtu %d", t.Transport.OrDefault(), orDash(t.TunnelIP), t.MTU)
		if t.Reality != nil {
			hint += " · reality sni " + orDash(t.Reality.ServerName)
		}
		r := row(t.Name, orDash(t.Endpoint), hint)
		switch {
		case t.Drained:
			r.Badge = "drained"
		case t.Reserve:
			r.Badge = "reserve"
		}
		sec.Rows = append(sec.Rows, r)
	}
	return sec
}

// clientVLESSSection shows the client-facing inbound. Client UUIDs are access
// credentials and are counted, never printed.
func clientVLESSSection(m *domain.MasterSpec) specSection {
	if m == nil || m.ClientVLESS == nil {
		return specSection{}
	}
	c := m.ClientVLESS
	sec := specSection{Title: "Client VLESS inbound"}
	sec.Rows = append(sec.Rows,
		row("Listen port", fmt.Sprintf("%d/tcp", c.ListenPort), ""),
		row("Camouflage", fmt.Sprintf("sni %s → dest %s", orDash(c.ServerName), orDash(c.Dest)), "REALITY masquerades as this host"),
		row("XHTTP", fmt.Sprintf("%s mode %s", orDash(c.XHTTPPath), orDash(c.XHTTPMode)), ""),
		row("Issued clients", fmt.Sprintf("%d", len(c.Clients)), "UUIDs are credentials and are not shown here"),
	)
	if names := clientNames(c.Clients); names != "" {
		sec.Rows = append(sec.Rows, row("Client names", names, ""))
	}
	return sec
}

// realitySection is the exit's REALITY server. It was missing from the page
// entirely, so an operator could not check dest/SNI/short-id against a client.
// The server UUID is a credential and stays out.
func realitySection(r *domain.RealityServerSpec) specSection {
	if r == nil {
		return specSection{}
	}
	sec := specSection{Title: "REALITY inbound"}
	sec.Rows = append(sec.Rows,
		row("Listen port", fmt.Sprintf("%d/tcp", r.ListenPort), ""),
		row("Camouflage", fmt.Sprintf("sni %s → dest %s", orDash(r.ServerName), orDash(r.Dest)), "dest must support X25519MLKEM768 or the handshake fails silently"),
		row("Short ID", orDash(r.ShortID), ""),
		row("XHTTP", fmt.Sprintf("%s mode %s", orDash(r.XHTTPPath), orDash(r.XHTTPMode)), ""),
	)
	if r.AllowEmptySNI || r.AllowIPv6 {
		sec.Rows = append(sec.Rows, row("Relaxations",
			joinNonEmptyValues(boolWord(r.AllowEmptySNI, "empty SNI allowed", ""), boolWord(r.AllowIPv6, "IPv6 allowed", "")), ""))
	}
	return sec
}

func routingSection(r domain.RoutingSpec) specSection {
	if r.EgressInterface == "" && len(r.DirectCIDRs) == 0 && r.ClientCIDR == "" {
		return specSection{}
	}
	sec := specSection{Title: "Routing"}
	sec.Rows = append(sec.Rows,
		row("Egress interface", orDash(r.EgressInterface), ""),
		row("Client CIDR", orDash(r.ClientCIDR), "the egress rule is scoped to this, never 'from all'"),
	)
	if len(r.DirectCIDRs) > 0 {
		sec.Rows = append(sec.Rows, row("Direct networks", fmt.Sprintf("%d prefixes", len(r.DirectCIDRs)), strings.Join(firstN(r.DirectCIDRs, 4), ", ")))
	}
	if r.FwMark > 0 {
		sec.Rows = append(sec.Rows, row("fwmark", fmt.Sprintf("%d", r.FwMark), ""))
	}
	return sec
}

// dnsSection reports operator overrides as a COUNT. Custom.Overrides is a
// free-form map, so its values cannot be allowlisted field by field and are not
// rendered at all.
func dnsSection(d domain.DNSFilterSpec) specSection {
	if !d.Enabled {
		return specSection{}
	}
	sec := specSection{Title: "DNS filter"}
	sec.Rows = append(sec.Rows,
		row("Bind", orDash(d.MgmtAddr), "management overlay only unless a client bind is set"),
		row("Upstreams", fmt.Sprintf("%d", len(d.Upstreams)), strings.Join(firstN(d.Upstreams, 3), ", ")),
	)
	if d.ClientBindAddr != "" {
		sec.Rows = append(sec.Rows, row("Client bind", d.ClientBindAddr, ""))
	}
	if n := len(d.Custom.Overrides); n > 0 {
		sec.Rows = append(sec.Rows, row("Operator overrides", fmt.Sprintf("%d", n), "values not shown — free-form config may carry secrets"))
	}
	return sec
}

func firewallSection(f domain.FirewallSpec) specSection {
	sec := specSection{Title: "Firewall"}
	sec.Rows = append(sec.Rows,
		row("AS blacklist", boolWord(f.ASBlacklist, "on", "off"), "drops scanner ASNs before they reach the data plane"),
	)
	if f.WGPort > 0 {
		sec.Rows = append(sec.Rows, row("WireGuard port", fmt.Sprintf("%d/udp", f.WGPort), ""))
	}
	if f.RealityPort > 0 {
		sec.Rows = append(sec.Rows, row("REALITY port", fmt.Sprintf("%d/tcp", f.RealityPort), ""))
	}
	if len(f.PublicTCPPorts) > 0 {
		sec.Rows = append(sec.Rows, row("Open TCP", intsCSV(f.PublicTCPPorts), "world-facing"))
	}
	if len(f.PublicUDPPorts) > 0 {
		sec.Rows = append(sec.Rows, row("Open UDP", intsCSV(f.PublicUDPPorts), "world-facing"))
	}
	if len(f.Whitelist) > 0 {
		sec.Rows = append(sec.Rows, row("Whitelist", fmt.Sprintf("%d prefixes", len(f.Whitelist)), strings.Join(firstN(f.Whitelist, 3), ", ")))
	}
	return sec
}

// hardeningSection surfaces a policy that was previously invisible: an operator
// who turned the managed sshd drop-in off had no way to confirm the controller
// agreed.
func hardeningSection(s domain.NodeSpec) specSection {
	sec := specSection{
		Title: "Host hardening",
		Note:  "unset means enabled — the fail-safe default for a controller that predates the knob.",
	}
	sshd := row("Managed sshd drop-in", boolWord(s.SSHDHardeningEnabled(), "on", "off — handed back to you"), "")
	f2b := row("fail2ban sshd jail", boolWord(s.Fail2banEnabled(), "on", "off — handed back to you"), "")
	if !s.SSHDHardeningEnabled() {
		sshd.Badge = "opted out"
	}
	if !s.Fail2banEnabled() {
		f2b.Badge = "opted out"
	}
	sec.Rows = append(sec.Rows, sshd, f2b)
	return sec
}

func exportersSection(s domain.NodeSpec) specSection {
	sec := specSection{Title: "Observability & thresholds"}
	sec.Rows = append(sec.Rows, row("Exporters",
		orNone(joinNonEmptyValues(
			boolWord(s.Exporters.Node, "node", ""),
			boolWord(s.Exporters.WG, "wireguard", ""),
			boolWord(s.Exporters.WARP, "warp", ""))), "scraped over the management overlay"))
	if s.EgressThroughputMinBps > 0 {
		sec.Rows = append(sec.Rows, row("Egress throughput floor", bitsPerSec(s.EgressThroughputMinBps),
			"below this the egress is treated as degraded and failover may fire"))
	}
	if s.EgressThroughputProbeURL != "" {
		sec.Rows = append(sec.Rows, row("Throughput probe", s.EgressThroughputProbeURL, ""))
	}
	return sec
}

// --- small helpers -----------------------------------------------------------

func row(label, value, hint string) specRow { return specRow{Label: label, Value: value, Hint: hint} }

func appendSection(dst []specSection, s specSection) []specSection {
	if s.Title == "" || len(s.Rows) == 0 {
		return dst
	}
	return append(dst, s)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "none"
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

func firstN(vals []string, n int) []string {
	if len(vals) <= n {
		return vals
	}
	return append(append([]string{}, vals[:n]...), "…")
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

// clientNames lists the operator-facing labels only. UUIDs and short-ids are
// access credentials and never appear.
func clientNames(cs []domain.VLESSClient) string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		if c.Name != "" {
			names = append(names, c.Name)
		}
	}
	return strings.Join(firstN(names, 8), ", ")
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
