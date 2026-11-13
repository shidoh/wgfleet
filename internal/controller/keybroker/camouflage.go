package keybroker

import (
	"context"
	"strings"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
)

// Own-domain camouflage (ADR-0039).
//
// A node with camouflage runs its own site and its REALITY inbounds accept both
// its domain and the fleet-default name. The site answers any SNI with the
// domain's certificate, so while the inbounds use it as target every name
// connects; while they are back on the fleet-default target (the site not up yet,
// or down) the domain does not. A peer therefore sends the domain only while the
// node reports serving it, and the fleet-default name otherwise — the name that
// connects in both states.

// camouflageSpec renders a node's camouflage, or nil when it has none or its agent
// is too old to carry it.
func (b *Broker) camouflageSpec(name string, cfg config.CamouflageConfig, publicIP, sshHost string, node domain.Node) *domain.CamouflageSpec {
	if !cfg.Enabled() || node.WireVersion < api.WireCamouflage {
		return nil
	}
	ip := config.CamouflagePublicIP(publicIP, sshHost, node.PublicIP)
	if ip == "" {
		b.warnOnce("camouflage-no-ip:"+name, publicIP+"|"+sshHost+"|"+node.PublicIP,
			"camouflage needs the node's public IP; leaving it off", "node", name)
		return nil
	}
	f := b.fleet.Camouflage
	return &domain.CamouflageSpec{
		Domain:      strings.ToLower(cfg.Domain),
		PublicHTTPS: cfg.PublicHTTPS,
		PublicIP:    ip,
		ACMEEmail:   f.ACMEEmail,
		ACMECA:      f.ACMECA,
		Image:       f.Image,
	}
}

// withCamouflagePorts opens the site's public ports: TCP/80 for the ACME HTTP-01
// challenge and the plain page, TCP/443 with public_https.
func withCamouflagePorts(spec *domain.NodeSpec) {
	if spec.Camouflage == nil {
		return
	}
	spec.Firewall.PublicTCPPorts = append(spec.Firewall.PublicTCPPorts, 80)
	if spec.Camouflage.PublicHTTPS {
		spec.Firewall.PublicTCPPorts = append(spec.Firewall.PublicTCPPorts, 443)
	}
}

// camouflageServerName is the SNI a peer sends toward a node: the node's own
// domain while the node reports serving it as its REALITY target, the fallback
// otherwise. Anything uncertain — an old agent, an unreadable status — gives the
// fallback, which connects either way.
func (b *Broker) camouflageServerName(ctx context.Context, name string, cfg config.CamouflageConfig, node domain.Node, fallback string) string {
	if !cfg.Enabled() || node.WireVersion < api.WireCamouflage {
		return fallback
	}
	st, err := b.store.GetStatus(ctx, name)
	if err != nil {
		return fallback
	}
	if want := strings.ToLower(cfg.Domain); st.CamouflageDomain == want {
		return want
	}
	return fallback
}
