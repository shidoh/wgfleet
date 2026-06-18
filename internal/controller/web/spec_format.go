package web

import (
	"fmt"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// formatSpec renders a NodeSpec as a readable, sectioned text block for the
// detail page. It shows the full desired state an operator needs to reason about
// the node — transport, obfuscation, peers, data plane, routing, DNS, firewall —
// not just a one-line summary. The controller-rendered spec carries no private
// keys (only public keys and obfuscation params, none of which are secret), so
// nothing needs redacting here.
func formatSpec(s domain.NodeSpec) string {
	var b strings.Builder

	// Header: role + egress chain (exits) or "master".
	fmt.Fprintf(&b, "role:    %s\n", s.Role)
	if s.Role == domain.RoleExit {
		fmt.Fprintf(&b, "egress:  %s", s.Egress)
		if chain := s.EgressMethods(); len(chain) > 1 {
			fmt.Fprintf(&b, "   (failover chain: %s)", joinEgress(chain))
		}
		b.WriteByte('\n')
	}
	if s.Decommission {
		b.WriteString("state:   DECOMMISSION (agent tears the data plane down)\n")
		return b.String()
	}

	formatWGServer(&b, s.WGServer)
	formatPeers(&b, s.Peers)
	formatMaster(&b, s.Master)
	formatRouting(&b, s.Routing)
	formatDNS(&b, s.DNS)
	formatFirewall(&b, s.Firewall)
	formatExporters(&b, s.Exporters, s.WARPMTU, s.Role)

	return b.String()
}

func formatWGServer(b *strings.Builder, w domain.WGServerSpec) {
	if w.ListenPort == 0 && w.AddressPool == "" {
		return
	}
	b.WriteString("\n[wg server]\n")
	fmt.Fprintf(b, "  listen port: %d/udp\n", w.ListenPort)
	fmt.Fprintf(b, "  address pool: %s\n", w.AddressPool)
	if w.Address != "" {
		fmt.Fprintf(b, "  own address: %s\n", w.Address)
	}
	fmt.Fprintf(b, "  mtu: %d\n", w.MTU)
	formatAWG(b, "  ", w.AWG)
	// The client end of this tunnel emits its OWN per-end decoy, distinct from the
	// interface's. Show it so the operator can verify clients are not fingerprinted
	// identically to the server.
	if l := w.ClientAWGLocal; l != nil {
		fmt.Fprintf(b, "  client awg junk (per-end, distinct from server): Jc=%d Jmin=%d Jmax=%d\n", l.Jc, l.Jmin, l.Jmax)
		if sig := joinNonEmpty(l.I1, l.I2, l.I3, l.I4, l.I5); sig != "" {
			fmt.Fprintf(b, "    client signatures: %s\n", sig)
		}
	}
}

// formatAWG renders the AmneziaWG obfuscation params in full. They are derived,
// non-secret values; showing them lets the operator verify the obfuscation a
// node (and its clients) actually use, and that S/H match across a tunnel.
func formatAWG(b *strings.Builder, indent string, awg *domain.AWGParams) {
	if awg == nil {
		fmt.Fprintf(b, "%sawg: (none — vanilla WireGuard)\n", indent)
		return
	}
	sh, lo := awg.Shared, awg.Local
	fmt.Fprintf(b, "%sawg shared (must match both ends): S1=%d S2=%d S3=%d S4=%d\n", indent, sh.S1, sh.S2, sh.S3, sh.S4)
	fmt.Fprintf(b, "%s  H1=%s H2=%s\n", indent, sh.H1.String(), sh.H2.String())
	fmt.Fprintf(b, "%s  H3=%s H4=%s\n", indent, sh.H3.String(), sh.H4.String())
	fmt.Fprintf(b, "%sawg junk (per-end): Jc=%d Jmin=%d Jmax=%d\n", indent, lo.Jc, lo.Jmin, lo.Jmax)
	if sig := joinNonEmpty(lo.I1, lo.I2, lo.I3, lo.I4, lo.I5); sig != "" {
		fmt.Fprintf(b, "%s  signatures: %s\n", indent, sig)
	}
}

func formatPeers(b *strings.Builder, peers []domain.PeerSpec) {
	if len(peers) == 0 {
		return
	}
	fmt.Fprintf(b, "\n[peers] %d\n", len(peers))
	for _, p := range peers {
		endpoint := p.Endpoint
		if endpoint == "" {
			endpoint = "(peer dials us — we are the server)"
		}
		fmt.Fprintf(b, "  - %s\n", p.Name)
		fmt.Fprintf(b, "      endpoint: %s\n", endpoint)
		fmt.Fprintf(b, "      allowed ips: %s\n", strings.Join(p.AllowedIPs, ", "))
		fmt.Fprintf(b, "      keepalive: %ds   mtu: %d\n", p.Keepalive, p.MTU)
		if p.PublicKey != "" {
			fmt.Fprintf(b, "      pubkey: %s\n", p.PublicKey)
		}
	}
}

func formatMaster(b *strings.Builder, m *domain.MasterSpec) {
	if m == nil {
		return
	}
	b.WriteString("\n[master data plane — mihomo]\n")
	fmt.Fprintf(b, "  bind: %s   redir-port: %s\n", m.BindAddress, redirPort(m.RedirPort))
	fmt.Fprintf(b, "  load-balance: %s\n", m.Balance)
	if m.ExternalController != "" {
		fmt.Fprintf(b, "  clash api: %s (mgmt only)\n", m.ExternalController)
		switch {
		case m.DashboardDisabled:
			b.WriteString("  dashboard: disabled\n")
		case m.DashboardURL != "":
			fmt.Fprintf(b, "  dashboard: %s (custom, agent-served)\n", m.DashboardURL)
		default:
			b.WriteString("  dashboard: metacubexd (default, agent-served)\n")
		}
	}
	if len(m.DirectCIDRs) > 0 {
		fmt.Fprintf(b, "  direct cidrs: %s\n", strings.Join(m.DirectCIDRs, ", "))
	}
	if len(m.DirectGeo) > 0 {
		fmt.Fprintf(b, "  direct geo: %s\n", strings.Join(m.DirectGeo, ", "))
	}
	if len(m.SnifferSkip) > 0 {
		fmt.Fprintf(b, "  sniffer skip: %s\n", strings.Join(m.SnifferSkip, ", "))
	}
	if len(m.ClientAdminPorts) > 0 {
		ports := make([]string, len(m.ClientAdminPorts))
		for i, p := range m.ClientAdminPorts {
			ports[i] = fmt.Sprintf("%d", p)
		}
		fmt.Fprintf(b, "  client admin ports (clients reach admin UIs): %s\n", strings.Join(ports, ", "))
	}
	fmt.Fprintf(b, "  exit tunnels: %d\n", len(m.ExitTunnels))
	for _, t := range m.ExitTunnels {
		drained := ""
		if t.Drained {
			drained = "  [DRAINED — kept as proxy, out of LB]"
		}
		fmt.Fprintf(b, "    - %-12s %s  tunnel-ip=%s mtu=%d%s\n", t.Name, t.Endpoint, t.TunnelIP, t.MTU, drained)
	}
	if m.Custom.HasOverrides() || len(m.Custom.Files) > 0 {
		fmt.Fprintf(b, "  custom: %d override key(s), %d extra file(s)\n", len(m.Custom.Overrides), len(m.Custom.Files))
	}
}

func formatRouting(b *strings.Builder, r domain.RoutingSpec) {
	if r.EgressInterface == "" && r.MasterIP == "" && len(r.DirectCIDRs) == 0 {
		return
	}
	b.WriteString("\n[policy routing]\n")
	if r.EgressInterface != "" {
		fmt.Fprintf(b, "  egress interface: %s\n", r.EgressInterface)
	} else {
		b.WriteString("  egress interface: (direct — no policy routing)\n")
	}
	if r.MasterIP != "" {
		fmt.Fprintf(b, "  master ip (kept direct): %s\n", r.MasterIP)
	}
	if r.FwMark != 0 {
		fmt.Fprintf(b, "  fwmark (handshake/reply direct): %#x\n", r.FwMark)
	}
	if len(r.DirectCIDRs) > 0 {
		fmt.Fprintf(b, "  direct cidrs: %s\n", strings.Join(r.DirectCIDRs, ", "))
	}
}

func formatDNS(b *strings.Builder, d domain.DNSFilterSpec) {
	if !d.Enabled {
		return
	}
	b.WriteString("\n[dns filter — blocky]\n")
	fmt.Fprintf(b, "  listen: %s (mgmt/loopback only)\n", d.MgmtAddr)
	fmt.Fprintf(b, "  ports: dns=%s tls=%s https=%s http=%s\n",
		dnsPort(d.Ports.DNS, 53), dnsPort(d.Ports.TLS, 853), dnsPort(d.Ports.HTTPS, 0), dnsPort(d.Ports.HTTP, 4000))
	if len(d.Upstreams) > 0 {
		fmt.Fprintf(b, "  upstreams: %s\n", strings.Join(d.Upstreams, ", "))
	} else {
		b.WriteString("  upstreams: (renderer defaults)\n")
	}
	if len(d.Allowlist) > 0 {
		fmt.Fprintf(b, "  allowlist: %s\n", strings.Join(d.Allowlist, ", "))
	}
	fmt.Fprintf(b, "  prometheus: %t   image: %s\n", d.Prometheus, d.Image)
}

func formatFirewall(b *strings.Builder, f domain.FirewallSpec) {
	if f.WGPort == 0 && !f.ASBlacklist && len(f.Whitelist) == 0 {
		return
	}
	b.WriteString("\n[firewall — nftables]\n")
	fmt.Fprintf(b, "  wg port allowed: %d/udp\n", f.WGPort)
	fmt.Fprintf(b, "  AS-blacklist (drop scanning ASNs): %t\n", f.ASBlacklist)
	if len(f.Whitelist) > 0 {
		fmt.Fprintf(b, "  whitelist: %s\n", strings.Join(f.Whitelist, ", "))
	}
}

func formatExporters(b *strings.Builder, e domain.ExportersSpec, warpMTU int, role domain.Role) {
	var on []string
	if e.Node {
		on = append(on, "node")
	}
	if e.WG {
		on = append(on, "wg")
	}
	if e.WARP {
		on = append(on, "warp")
	}
	if len(on) == 0 && warpMTU == 0 {
		return
	}
	b.WriteString("\n[exporters / misc]\n")
	if len(on) > 0 {
		fmt.Fprintf(b, "  metrics: %s\n", strings.Join(on, ", "))
	}
	if role == domain.RoleExit && warpMTU > 0 {
		fmt.Fprintf(b, "  warp mtu: %d\n", warpMTU)
	}
}

func redirPort(p int) string {
	if p == 0 {
		return "0 (mihomo default 7895)"
	}
	return fmt.Sprintf("%d", p)
}

func dnsPort(p, def int) string {
	if p == 0 {
		if def == 0 {
			return "off"
		}
		return fmt.Sprintf("%d(default)", def)
	}
	return fmt.Sprintf("%d", p)
}

func joinEgress(chain []domain.EgressMethod) string {
	parts := make([]string, len(chain))
	for i, m := range chain {
		parts[i] = string(m)
	}
	return strings.Join(parts, " → ")
}

func joinNonEmpty(vals ...string) string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, " ")
}
