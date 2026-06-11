package web

import (
	"fmt"
	"strings"

	"github.com/shidoh/wgfleet/internal/domain"
)

// formatSpec renders a NodeSpec as a compact, readable text block for the detail
// page. The controller-rendered spec carries no private keys (only public keys
// and obfuscation params), so nothing needs redacting here.
func formatSpec(s domain.NodeSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "role:      %s\n", s.Role)
	if s.Role == domain.RoleExit {
		fmt.Fprintf(&b, "egress:    %s\n", s.Egress)
	}

	w := s.WGServer
	fmt.Fprintf(&b, "\n[wg server]\n")
	fmt.Fprintf(&b, "  listen:  %d\n", w.ListenPort)
	fmt.Fprintf(&b, "  pool:    %s\n", w.AddressPool)
	if w.Address != "" {
		fmt.Fprintf(&b, "  address: %s\n", w.Address)
	}
	fmt.Fprintf(&b, "  mtu:     %d\n", w.MTU)
	if w.AWG != nil {
		fmt.Fprintf(&b, "  awg:     S1=%d S2=%d H1=%s … (obfuscated)\n",
			w.AWG.Shared.S1, w.AWG.Shared.S2, w.AWG.Shared.H1)
	}

	if len(s.Peers) > 0 {
		fmt.Fprintf(&b, "\n[peers] %d\n", len(s.Peers))
		for _, p := range s.Peers {
			endpoint := p.Endpoint
			if endpoint == "" {
				endpoint = "(dials us)"
			}
			fmt.Fprintf(&b, "  - %s  %s  allowed=%s\n", p.Name, endpoint, strings.Join(p.AllowedIPs, ","))
		}
	}

	if m := s.Master; m != nil {
		fmt.Fprintf(&b, "\n[master / mihomo]\n")
		fmt.Fprintf(&b, "  bind:    %s\n", m.BindAddress)
		fmt.Fprintf(&b, "  redir:   %d\n", m.RedirPort)
		fmt.Fprintf(&b, "  balance: %s\n", m.Balance)
		fmt.Fprintf(&b, "  exit tunnels: %d\n", len(m.ExitTunnels))
		for _, t := range m.ExitTunnels {
			fmt.Fprintf(&b, "    - %s  %s  ip=%s mtu=%d\n", t.Name, t.Endpoint, t.TunnelIP, t.MTU)
		}
		if len(m.DirectGeo) > 0 {
			fmt.Fprintf(&b, "  direct geo: %s\n", strings.Join(m.DirectGeo, ","))
		}
		if m.Custom.HasOverrides() {
			fmt.Fprintf(&b, "  custom: %d override key(s), %d extra file(s)\n",
				len(m.Custom.Overrides), len(m.Custom.Files))
		}
	}

	if s.Routing.EgressInterface != "" {
		fmt.Fprintf(&b, "\n[routing]\n  egress iface: %s\n  master ip: %s\n",
			s.Routing.EgressInterface, s.Routing.MasterIP)
	}
	if s.DNS.Enabled {
		port := s.DNS.Ports.DNS
		if port == 0 {
			port = 53
		}
		fmt.Fprintf(&b, "\n[dns] blocky listen %s:%d (mgmt only)  prometheus=%t\n",
			s.DNS.MgmtAddr, port, s.DNS.Prometheus)
	}
	if s.Firewall.WGPort > 0 {
		fmt.Fprintf(&b, "\n[firewall] wg-port %d  as-blacklist=%t\n", s.Firewall.WGPort, s.Firewall.ASBlacklist)
	}
	return b.String()
}
