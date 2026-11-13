package keybroker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/compose"
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
	if !exit.Transports.Reality.ExitInitiated ||
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

// portalIDs returns the VLESS UUID and short-id of exit's bridge at master's
// portal: random, minted once per pair and kept in the store. Never derived from
// names — an id any exit could compute would let it register under another
// exit's reverse tag and receive that exit's client streams.
func (b *Broker) portalIDs(ctx context.Context, exitName, masterName string) (uuid, shortID string, err error) {
	uuid, shortID, err = mintPairIDs(ctx, exitName, masterName, b.store.EnsureRealityPortalIDs)
	if err != nil {
		return "", "", fmt.Errorf("reality portal ids: %w", err)
	}
	return uuid, shortID, nil
}

// tunnelIDs returns the VLESS UUID and short-id of the master-initiated REALITY
// tunnel from master to exit, minted and kept like portalIDs. Derived from the
// node names they could be computed by anyone who knew the names.
func (b *Broker) tunnelIDs(ctx context.Context, exitName, masterName string) (uuid, shortID string, err error) {
	uuid, shortID, err = mintPairIDs(ctx, exitName, masterName, b.store.EnsureRealityTunnelIDs)
	if err != nil {
		return "", "", fmt.Errorf("reality tunnel ids: %w", err)
	}
	return uuid, shortID, nil
}

// mintPairIDs draws a random v4 UUID and 8-byte short-id and hands them to
// ensure, which keeps the pair's first ones; it returns what is stored.
func mintPairIDs(ctx context.Context, exitName, masterName string,
	ensure func(ctx context.Context, master, exit, uuid, shortID string) (string, string, error),
) (uuid, shortID string, err error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	u := raw[:16]
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	candUUID := fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	candSID := hex.EncodeToString(raw[16:24])
	uuid, shortID, err = ensure(ctx, masterName, exitName, candUUID, candSID)
	if err != nil {
		return "", "", fmt.Errorf("exit %q at master %q: %w: %w", exitName, masterName, store.ErrUnreadable, err)
	}
	return uuid, shortID, nil
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
		uuid, sid, err := b.portalIDs(ctx, exit.Name, t.Master.Name)
		if err != nil {
			return nil, err
		}
		sni, _ := b.portalCamouflage(t.Master)
		if t.Master.Camouflage.Enabled() {
			masterNode, _, err := b.lookupPubKey(ctx, t.Master.Name)
			if err != nil {
				return nil, err
			}
			sni = b.camouflageServerName(ctx, t.Master.Name, t.Master.Camouflage, masterNode, sni)
		}
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

// realityPortalSpec builds a master's portal for the exits that dial it. The
// image is the pinned default: the portal and every bridge run one xray.
func (b *Broker) realityPortalSpec(master config.MasterConfig, clients []domain.RealityPortalClient) *domain.RealityPortalSpec {
	sni, dest := b.portalCamouflage(master)
	return &domain.RealityPortalSpec{
		ListenPort: master.RealityPortalListenPort(),
		SocksPort:  domain.RealityPortalSocksPort,
		ServerName: sni,
		Dest:       dest,
		Image:      compose.DefaultXrayImage,
		Clients:    clients,
	}
}
