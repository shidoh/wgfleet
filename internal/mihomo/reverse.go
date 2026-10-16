package mihomo

import (
	"fmt"
	"net/netip"

	"github.com/shidoh/wgfleet/internal/domain"
)

// reverseRealityProxy renders the proxy for an exit in the exit-initiated
// REALITY mode (ADR-0038): the exit dialled the master's portal, so mihomo
// reaches it through the portal's SOCKS inbound as the exit's user, and the
// portal sends the stream down that exit's reverse flow. UDP rides SOCKS5
// ASSOCIATE.
func reverseRealityProxy(in RenderInput, t domain.ExitTunnel) (map[string]any, error) {
	exit := t.ExitNode()
	switch {
	case in.Spec.RealityPortal == nil:
		return nil, fmt.Errorf("exit %q: reverse reality tunnel but the master runs no portal", t.Name)
	case in.PortalSocksAddr == "":
		return nil, fmt.Errorf("exit %q: reverse reality tunnel but no portal SOCKS address", t.Name)
	case in.PortalPasswords[exit] == "":
		return nil, fmt.Errorf("exit %q: reverse reality tunnel but no portal SOCKS password", t.Name)
	}
	return map[string]any{
		"name":     t.Name,
		"type":     "socks5",
		"server":   in.PortalSocksAddr,
		"port":     in.Spec.RealityPortal.ResolvedSocksPort(),
		"username": exit,
		"password": in.PortalPasswords[exit],
		"udp":      true,
	}, nil
}

// portalSocksGuard is the REJECT rule that keeps client traffic off the portal's
// SOCKS address: a client's DIRECT connection leaves from mihomo and could
// otherwise reach it. On the loopback the whole 127/8 is rejected — nothing a
// client asks for lives there. Empty without a portal.
func portalSocksGuard(in RenderInput) string {
	if in.Spec.RealityPortal == nil || in.PortalSocksAddr == "" {
		return ""
	}
	addr, err := netip.ParseAddr(in.PortalSocksAddr)
	if err != nil {
		return ""
	}
	prefix := netip.PrefixFrom(addr, addr.BitLen())
	if addr.IsLoopback() && addr.Is4() {
		prefix = netip.MustParsePrefix("127.0.0.0/8")
	}
	return "IP-CIDR," + prefix.String() + ",REJECT,no-resolve"
}
