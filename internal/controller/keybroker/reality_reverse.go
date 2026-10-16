package keybroker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
)

// Exit-initiated REALITY (ADR-0038). The mode is the exit's; the tunnels are
// per master. An exit is in the mode when its flag is set and its agent can
// carry the bridge. Each master then gets a reverse tunnel to it only when that
// master is ready itself — a lagging master costs its own tunnel, never the
// others' (falling back to forward REALITY is exactly what the filter kills).

// portalTarget is one master's portal as an exit in the mode dials it.
type portalTarget struct {
	Master    config.MasterConfig
	Addr      netip.AddrPort
	PublicKey string
}

// realityReverse reports whether exit is in the exit-initiated REALITY mode.
// Both renderers ask it, so the exit's bridge and the masters' tunnels can
// never disagree about the mode.
func (b *Broker) realityReverse(exit config.ExitConfig, exitNode domain.Node) bool {
	if !b.reverseOpen || !exit.Transports.Reality.ExitInitiated ||
		!slices.Contains(exit.EnabledTransports(), domain.TransportRealityXHTTP) {
		return false
	}
	if exitNode.WireVersion < api.WireRealityReverse {
		b.warnOnce("reality-reverse-exit-wire:"+exit.Name, fmt.Sprint(exitNode.WireVersion),
			"exit-initiated REALITY not rendered: the exit agent is too old to run the bridge; it keeps listening",
			"exit", exit.Name, "exit_wire", exitNode.WireVersion, "need_wire", api.WireRealityReverse)
		return false
	}
	b.forgetWarned("reality-reverse-exit-wire:" + exit.Name)
	return true
}

// portalTarget reports whether master is ready to serve exit in the mode: on
// wire 14, its portal key published, a public IPv4 the exit can reach. A
// master that is not gets no REALITY tunnel to the exit.
func (b *Broker) portalTarget(exit config.ExitConfig, master config.MasterConfig, masterNode domain.Node) (portalTarget, bool) {
	key := "reality-reverse-master:" + master.Name + "/" + exit.Name
	refuse := func(why, detail string) (portalTarget, bool) {
		b.warnOnce(key, why+"|"+detail,
			"exit-initiated REALITY: master not ready, it carries no REALITY tunnel to this exit ("+why+")",
			"exit", exit.Name, "master", master.Name, "detail", detail)
		return portalTarget{}, false
	}
	if masterNode.WireVersion < api.WireRealityReverse {
		return refuse("master agent below wire 14", fmt.Sprint(masterNode.WireVersion))
	}
	if masterNode.RealityPortalPublicKey == "" {
		return refuse("portal key not published", "")
	}
	ip, ok := masterRoutableIP(master, masterNode)
	if !ok || !config.IsKnockableIPv4(ip) {
		return refuse("no public IPv4 the exit can reach", master.PublicIP+"|"+masterNode.PublicIP)
	}
	b.forgetWarned(key)
	return portalTarget{
		Master:    master,
		Addr:      netip.AddrPortFrom(ip, uint16(master.RealityPortalListenPort())),
		PublicKey: masterNode.RealityPortalPublicKey,
	}, true
}

// portalTargets lists the masters ready to serve exit, by slot. Call it only
// for an exit in the mode: it reads every master's record.
func (b *Broker) portalTargets(ctx context.Context, exit config.ExitConfig) ([]portalTarget, error) {
	masters := slices.Clone(b.fleet.Masters)
	sort.SliceStable(masters, func(i, j int) bool { return masters[i].Slot < masters[j].Slot })
	var out []portalTarget
	for _, m := range masters {
		node, err := b.store.GetNode(ctx, m.Name)
		if errors.Is(err, store.ErrNotFound) {
			b.warnOnce("reality-reverse-master:"+m.Name+"/"+exit.Name, "unregistered",
				"exit-initiated REALITY: master not ready, it carries no REALITY tunnel to this exit (never registered)",
				"exit", exit.Name, "master", m.Name)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("exit %q: read master %q for its portal: %w", exit.Name, m.Name, err)
		}
		if t, ok := b.portalTarget(exit, m, node); ok {
			out = append(out, t)
		}
	}
	return out, nil
}

// portalIDs derives the VLESS UUID and short-id of exit's bridge at master's
// portal. Per pair and distinct from the forward identity, which every master
// of the exit shares.
func portalIDs(exitName, masterName string) (uuid, shortID string) {
	return deriveRealityIDs(fmt.Sprintf("%s|%s|%s|reality-portal", awgSalt, masterName, exitName))
}

// portalCamouflage resolves a master's portal SNI and dest: the master's
// reality_portal block, then the fleet default, then the safe built-in.
func (b *Broker) portalCamouflage(m config.MasterConfig) (sni, dest string) {
	r := m.RealityPortal
	sni = firstNonEmpty(r.SNI, r.DestDomain, b.fleet.RealityDefaultSNI, DefaultRealitySNI)
	dest = firstNonEmpty(r.DestHostPort(), b.fleet.RealityDefaultDest, sni+":443")
	return sni, dest
}

// bridgeFor builds the exit's bridge: one portal per ready master. With none
// ready the list is empty and the exit dials nothing — it never falls back to
// listening, which is the flow the filter kills.
func (b *Broker) bridgeFor(ctx context.Context, exit config.ExitConfig) (*domain.RealityBridgeSpec, error) {
	targets, err := b.portalTargets(ctx, exit)
	if err != nil {
		return nil, err
	}
	bridge := &domain.RealityBridgeSpec{}
	for _, t := range targets {
		uuid, sid := portalIDs(exit.Name, t.Master.Name)
		sni, _ := b.portalCamouflage(t.Master)
		bridge.Portals = append(bridge.Portals, domain.RealityPortalPeer{
			Master:      t.Master.Name,
			Address:     t.Addr.String(),
			PublicKey:   t.PublicKey,
			UUID:        uuid,
			ShortID:     sid,
			ServerName:  sni,
			Fingerprint: exit.Transports.Reality.Fingerprint,
		})
	}
	return bridge, nil
}
