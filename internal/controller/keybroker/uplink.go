package keybroker

import (
	"context"
	"net/netip"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
)

// uplinkProbeTargets lists the other masters self dials to measure its own
// uplink: each peer's public IP at a TCP port that peer opens to the world.
//
// A peer is left out, not guessed at, when it has no IP literal (config or store)
// or no world-open TCP port: a target that cannot answer by construction would
// read as a dead uplink. A store error skips that one peer — the measurement is
// observation, and it must never cost the master its spec.
func (b *Broker) uplinkProbeTargets(ctx context.Context, self config.MasterConfig) []domain.UplinkProbeTarget {
	var out []domain.UplinkProbeTarget
	for _, peer := range b.fleet.Masters {
		if peer.Name == self.Name {
			continue
		}
		port := uplinkProbePort(peer)
		if port == 0 {
			continue
		}
		node, _, err := b.lookupPubKey(ctx, peer.Name)
		if err != nil {
			b.warnOnce("uplink-probe-store:"+peer.Name, err.Error(),
				"skipping a peer master in the uplink probe targets: the store could not answer",
				"master", self.Name, "peer", peer.Name, "err", err)
			continue
		}
		ip, ok := masterRoutableIP(peer, node)
		if !ok {
			continue
		}
		out = append(out, domain.UplinkProbeTarget{Name: peer.Name, Addr: netip.AddrPortFrom(ip, uint16(port))})
	}
	return out
}

// uplinkProbePort is the TCP port a master keeps open to the world, or 0. The
// client VLESS inbound comes first: the master exists to keep it answering.
// public_tcp_ports is the fallback — it holds what an operator opened, which may
// be a listener started by hand and down most of the time.
func uplinkProbePort(m config.MasterConfig) int {
	if m.ClientVLESS.Enabled {
		return m.ClientVLESSListenPort()
	}
	for _, p := range m.PublicTCPPorts {
		if p > 0 && p <= 65535 {
			return p
		}
	}
	return 0
}
