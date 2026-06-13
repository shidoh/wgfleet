// Package api converts between the generated protobuf wire types (pb) and the
// internal domain types. Keeping conversion in one place means the wire format
// never leaks into controller/agent business logic, and a proto change surfaces
// as a compile error here rather than silently across the codebase.
package api

import (
	"encoding/json"
	"log/slog"
	"time"

	pb "github.com/shidoh/wgfleet/internal/api/pb/wgfleet/v1"
	"github.com/shidoh/wgfleet/internal/domain"
)

// SpecToProto renders a domain NodeSpec onto the wire.
func SpecToProto(s domain.NodeSpec) *pb.NodeSpec {
	out := &pb.NodeSpec{
		Role:      string(s.Role),
		Egress:    string(s.Egress),
		WgServer:  wgServerToProto(s.WGServer),
		Dns:       dnsToProto(s.DNS),
		Firewall:  firewallToProto(s.Firewall),
		Routing:   routingToProto(s.Routing),
		Exporters: &pb.ExportersSpec{Node: s.Exporters.Node, Wg: s.Exporters.WG, Warp: s.Exporters.WARP},
	}
	for _, p := range s.Peers {
		out.Peers = append(out.Peers, peerToProto(p))
	}
	out.Master = masterToProto(s.Master)
	out.Decommission = s.Decommission
	out.WarpMtu = int32(s.WARPMTU)
	for _, m := range s.EgressChain {
		out.EgressChain = append(out.EgressChain, string(m))
	}
	return out
}

// SpecFromProto parses a wire NodeSpec back into the domain type.
func SpecFromProto(p *pb.NodeSpec) domain.NodeSpec {
	if p == nil {
		return domain.NodeSpec{}
	}
	s := domain.NodeSpec{
		Role:     domain.Role(p.GetRole()),
		Egress:   domain.EgressMethod(p.GetEgress()),
		WGServer: wgServerFromProto(p.GetWgServer()),
		DNS:      dnsFromProto(p.GetDns()),
		Firewall: firewallFromProto(p.GetFirewall()),
		Routing:  routingFromProto(p.GetRouting()),
	}
	if e := p.GetExporters(); e != nil {
		s.Exporters = domain.ExportersSpec{Node: e.GetNode(), WG: e.GetWg(), WARP: e.GetWarp()}
	}
	for _, pp := range p.GetPeers() {
		s.Peers = append(s.Peers, peerFromProto(pp))
	}
	s.Master = masterFromProto(p.GetMaster())
	s.Decommission = p.GetDecommission()
	s.WARPMTU = int(p.GetWarpMtu())
	for _, m := range p.GetEgressChain() {
		s.EgressChain = append(s.EgressChain, domain.EgressMethod(m))
	}
	return s
}

func masterToProto(m *domain.MasterSpec) *pb.MasterSpec {
	if m == nil {
		return nil
	}
	out := &pb.MasterSpec{
		BindAddress:        m.BindAddress,
		RedirPort:          int32(m.RedirPort),
		ExternalController: m.ExternalController,
		Balance:            m.Balance,
		DirectCidrs:        append([]string(nil), m.DirectCIDRs...),
		DirectGeo:          append([]string(nil), m.DirectGeo...),
		SnifferSkip:        append([]string(nil), m.SnifferSkip...),
		Custom:             customToProto(m.Custom),
		Compose:            composeToProto(m.Compose),
	}
	for _, t := range m.ExitTunnels {
		out.ExitTunnels = append(out.ExitTunnels, &pb.ExitTunnel{
			Name:            t.Name,
			Endpoint:        t.Endpoint,
			ServerPublicKey: t.ServerPublicKey,
			PresharedKey:    t.PresharedKey,
			TunnelIp:        t.TunnelIP,
			Mtu:             int32(t.MTU),
			Awg:             awgToProto(t.AWG),
			Drained:         t.Drained,
		})
	}
	return out
}

func masterFromProto(m *pb.MasterSpec) *domain.MasterSpec {
	if m == nil {
		return nil
	}
	out := &domain.MasterSpec{
		BindAddress:        m.GetBindAddress(),
		RedirPort:          int(m.GetRedirPort()),
		ExternalController: m.GetExternalController(),
		Balance:            m.GetBalance(),
		DirectCIDRs:        append([]string(nil), m.GetDirectCidrs()...),
		DirectGeo:          append([]string(nil), m.GetDirectGeo()...),
		SnifferSkip:        append([]string(nil), m.GetSnifferSkip()...),
		Custom:             customFromProto(m.GetCustom()),
		Compose:            composeFromProto(m.GetCompose()),
	}
	for _, t := range m.GetExitTunnels() {
		out.ExitTunnels = append(out.ExitTunnels, domain.ExitTunnel{
			Name:            t.GetName(),
			Endpoint:        t.GetEndpoint(),
			ServerPublicKey: t.GetServerPublicKey(),
			PresharedKey:    t.GetPresharedKey(),
			TunnelIP:        t.GetTunnelIp(),
			MTU:             int(t.GetMtu()),
			AWG:             awgFromProto(t.GetAwg()),
			Drained:         t.GetDrained(),
		})
	}
	return out
}

func customToProto(c domain.CustomConfig) *pb.CustomConfig {
	if !c.HasOverrides() {
		return nil
	}
	out := &pb.CustomConfig{}
	if len(c.Overrides) > 0 {
		// Arbitrary nested overrides cross the wire as JSON. A marshal error is not
		// expected for the map[string]any we accept, but if it ever happens, LOG it
		// — silently dropping the overrides would render the node's config without
		// the operator's customizations and no one would know why.
		if b, err := json.Marshal(c.Overrides); err == nil {
			out.OverridesJson = string(b)
		} else {
			slog.Error("dropping config overrides: JSON marshal failed", "err", err)
		}
	}
	for _, f := range c.Files {
		out.Files = append(out.Files, &pb.ManagedFile{Path: f.Path, Content: f.Content, Secret: f.Secret})
	}
	return out
}

func customFromProto(c *pb.CustomConfig) domain.CustomConfig {
	if c == nil {
		return domain.CustomConfig{}
	}
	out := domain.CustomConfig{}
	if c.GetOverridesJson() != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(c.GetOverridesJson()), &m); err == nil {
			out.Overrides = m
		} else {
			// A decode failure means the agent would reconcile without the operator's
			// overrides — never silently; log so the divergence is diagnosable.
			slog.Error("dropping config overrides: JSON unmarshal failed", "err", err)
		}
	}
	for _, f := range c.GetFiles() {
		out.Files = append(out.Files, domain.ManagedFile{Path: f.GetPath(), Content: f.GetContent(), Secret: f.GetSecret()})
	}
	return out
}

func composeToProto(c domain.ComposeSpec) *pb.ComposeSpec {
	if !c.Enabled() && c.PublicIP == "" && len(c.ClientDNS) == 0 && c.ClientAllowedIPs == "" {
		return nil
	}
	return &pb.ComposeSpec{
		WgEasyImage:      c.WGEasyImage,
		MihomoImage:      c.MihomoImage,
		PublicIp:         c.PublicIP,
		WgEasyWebPort:    int32(c.WGEasyWebPort),
		ClientDns:        append([]string(nil), c.ClientDNS...),
		ClientAllowedIps: c.ClientAllowedIPs,
	}
}

func composeFromProto(c *pb.ComposeSpec) domain.ComposeSpec {
	if c == nil {
		return domain.ComposeSpec{}
	}
	return domain.ComposeSpec{
		WGEasyImage:      c.GetWgEasyImage(),
		MihomoImage:      c.GetMihomoImage(),
		PublicIP:         c.GetPublicIp(),
		WGEasyWebPort:    int(c.GetWgEasyWebPort()),
		ClientDNS:        append([]string(nil), c.GetClientDns()...),
		ClientAllowedIPs: c.GetClientAllowedIps(),
	}
}

func wgServerToProto(w domain.WGServerSpec) *pb.WGServerSpec {
	return &pb.WGServerSpec{
		ListenPort:  int32(w.ListenPort),
		AddressPool: w.AddressPool,
		Address:     w.Address,
		Mtu:         int32(w.MTU),
		Awg:         awgToProto(w.AWG),
	}
}

func wgServerFromProto(w *pb.WGServerSpec) domain.WGServerSpec {
	if w == nil {
		return domain.WGServerSpec{}
	}
	return domain.WGServerSpec{
		ListenPort:  int(w.GetListenPort()),
		AddressPool: w.GetAddressPool(),
		Address:     w.GetAddress(),
		MTU:         int(w.GetMtu()),
		AWG:         awgFromProto(w.GetAwg()),
	}
}

func peerToProto(p domain.PeerSpec) *pb.PeerSpec {
	return &pb.PeerSpec{
		Name:       p.Name,
		PublicKey:  p.PublicKey,
		Endpoint:   p.Endpoint,
		AllowedIps: append([]string(nil), p.AllowedIPs...),
		Keepalive:  int32(p.Keepalive),
		Mtu:        int32(p.MTU),
	}
}

func peerFromProto(p *pb.PeerSpec) domain.PeerSpec {
	return domain.PeerSpec{
		Name:       p.GetName(),
		PublicKey:  p.GetPublicKey(),
		Endpoint:   p.GetEndpoint(),
		AllowedIPs: append([]string(nil), p.GetAllowedIps()...),
		Keepalive:  int(p.GetKeepalive()),
		MTU:        int(p.GetMtu()),
	}
}

func awgToProto(a *domain.AWGParams) *pb.AWGParams {
	if a == nil {
		return nil
	}
	s := a.Shared
	return &pb.AWGParams{
		Shared: &pb.AWGShared{
			H1: headerToProto(s.H1), H2: headerToProto(s.H2),
			H3: headerToProto(s.H3), H4: headerToProto(s.H4),
			S1: int32(s.S1), S2: int32(s.S2), S3: int32(s.S3), S4: int32(s.S4),
		},
		Local: &pb.AWGLocal{
			Jc: int32(a.Local.Jc), Jmin: int32(a.Local.Jmin), Jmax: int32(a.Local.Jmax),
			I1: a.Local.I1, I2: a.Local.I2, I3: a.Local.I3, I4: a.Local.I4, I5: a.Local.I5,
		},
	}
}

func awgFromProto(a *pb.AWGParams) *domain.AWGParams {
	if a == nil {
		return nil
	}
	out := domain.AWGParams{}
	if s := a.GetShared(); s != nil {
		out.Shared = domain.AWGShared{
			H1: headerFromProto(s.GetH1()), H2: headerFromProto(s.GetH2()),
			H3: headerFromProto(s.GetH3()), H4: headerFromProto(s.GetH4()),
			S1: int(s.GetS1()), S2: int(s.GetS2()), S3: int(s.GetS3()), S4: int(s.GetS4()),
		}
	}
	if l := a.GetLocal(); l != nil {
		out.Local = domain.AWGLocal{
			Jc: int(l.GetJc()), Jmin: int(l.GetJmin()), Jmax: int(l.GetJmax()),
			I1: l.GetI1(), I2: l.GetI2(), I3: l.GetI3(), I4: l.GetI4(), I5: l.GetI5(),
		}
	}
	return &out
}

func headerToProto(h domain.AWGHeader) *pb.AWGHeader {
	return &pb.AWGHeader{Min: h.Min, Max: h.Max}
}

func headerFromProto(h *pb.AWGHeader) domain.AWGHeader {
	if h == nil {
		return domain.AWGHeader{}
	}
	return domain.AWGHeader{Min: h.GetMin(), Max: h.GetMax()}
}

func dnsToProto(d domain.DNSFilterSpec) *pb.DNSFilterSpec {
	out := &pb.DNSFilterSpec{
		Enabled:   d.Enabled,
		MgmtAddr:  d.MgmtAddr,
		Upstreams: append([]string(nil), d.Upstreams...),
		Ports: &pb.DNSPorts{
			Dns:   int32(d.Ports.DNS),
			Tls:   int32(d.Ports.TLS),
			Https: int32(d.Ports.HTTPS),
			Http:  int32(d.Ports.HTTP),
		},
		Allowlist:  append([]string(nil), d.Allowlist...),
		Prometheus: d.Prometheus,
		Image:      d.Image,
		Custom:     customToProto(d.Custom),
	}
	for _, b := range d.BootstrapDNS {
		out.BootstrapDns = append(out.BootstrapDns, &pb.BootstrapUpstream{
			Upstream: b.Upstream,
			Ips:      append([]string(nil), b.IPs...),
		})
	}
	return out
}

func dnsFromProto(d *pb.DNSFilterSpec) domain.DNSFilterSpec {
	if d == nil {
		return domain.DNSFilterSpec{}
	}
	out := domain.DNSFilterSpec{
		Enabled:    d.GetEnabled(),
		MgmtAddr:   d.GetMgmtAddr(),
		Upstreams:  append([]string(nil), d.GetUpstreams()...),
		Allowlist:  append([]string(nil), d.GetAllowlist()...),
		Prometheus: d.GetPrometheus(),
		Image:      d.GetImage(),
		Custom:     customFromProto(d.GetCustom()),
	}
	if p := d.GetPorts(); p != nil {
		out.Ports = domain.DNSPorts{
			DNS:   int(p.GetDns()),
			TLS:   int(p.GetTls()),
			HTTPS: int(p.GetHttps()),
			HTTP:  int(p.GetHttp()),
		}
	}
	for _, b := range d.GetBootstrapDns() {
		out.BootstrapDNS = append(out.BootstrapDNS, domain.BootstrapUpstream{
			Upstream: b.GetUpstream(),
			IPs:      append([]string(nil), b.GetIps()...),
		})
	}
	return out
}

func firewallToProto(f domain.FirewallSpec) *pb.FirewallSpec {
	return &pb.FirewallSpec{
		AsBlacklist: f.ASBlacklist,
		Whitelist:   append([]string(nil), f.Whitelist...),
		WgPort:      int32(f.WGPort),
	}
}

func firewallFromProto(f *pb.FirewallSpec) domain.FirewallSpec {
	if f == nil {
		return domain.FirewallSpec{}
	}
	return domain.FirewallSpec{
		ASBlacklist: f.GetAsBlacklist(),
		Whitelist:   append([]string(nil), f.GetWhitelist()...),
		WGPort:      int(f.GetWgPort()),
	}
}

func routingToProto(r domain.RoutingSpec) *pb.RoutingSpec {
	return &pb.RoutingSpec{
		EgressInterface: r.EgressInterface,
		DirectCidrs:     append([]string(nil), r.DirectCIDRs...),
		MasterIp:        r.MasterIP,
		Fwmark:          int32(r.FwMark),
	}
}

func routingFromProto(r *pb.RoutingSpec) domain.RoutingSpec {
	if r == nil {
		return domain.RoutingSpec{}
	}
	return domain.RoutingSpec{
		EgressInterface: r.GetEgressInterface(),
		DirectCIDRs:     append([]string(nil), r.GetDirectCidrs()...),
		MasterIP:        r.GetMasterIp(),
		FwMark:          int(r.GetFwmark()),
	}
}

// StatusFromProto converts a wire StatusReport into a domain NodeStatus for the
// given node. The node ID comes from the authenticated session, not the wire.
func StatusFromProto(nodeID string, r *pb.StatusReport) domain.NodeStatus {
	st := domain.NodeStatus{
		NodeID:         nodeID,
		State:          domain.NodeState(r.GetState()),
		EgressIP:       r.GetEgressIp(),
		ReconcileError: r.GetReconcileError(),
	}
	if hs := r.GetLastHandshakeUnix(); hs > 0 {
		st.LastHandshake = time.Unix(hs, 0).UTC()
	}
	for _, c := range r.GetChecks() {
		st.Checks = append(st.Checks, domain.HealthCheck{
			Name:    c.GetName(),
			OK:      c.GetOk(),
			Detail:  c.GetDetail(),
			Latency: time.Duration(c.GetLatencyMs()) * time.Millisecond,
		})
	}
	return st
}

// StatusToProto converts a domain NodeStatus into a wire StatusReport.
func StatusToProto(s domain.NodeStatus) *pb.StatusReport {
	r := &pb.StatusReport{
		State:          string(s.State),
		EgressIp:       s.EgressIP,
		ReconcileError: s.ReconcileError,
	}
	if !s.LastHandshake.IsZero() {
		r.LastHandshakeUnix = s.LastHandshake.Unix()
	}
	for _, c := range s.Checks {
		r.Checks = append(r.Checks, &pb.HealthCheck{
			Name:      c.Name,
			Ok:        c.OK,
			Detail:    c.Detail,
			LatencyMs: c.Latency.Milliseconds(),
		})
	}
	return r
}
