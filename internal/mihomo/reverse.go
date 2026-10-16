package mihomo

import (
	"fmt"

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
