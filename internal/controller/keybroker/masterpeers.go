package keybroker

import (
	"context"
	"fmt"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// masterPeers renders the peers ONE master contributes to an exit's interface:
// its legacy shared-identity peer and/or its per-tunnel peer, as the exit's
// per_tunnel_key phase dictates (ADR-0030), each on its own address. It also
// returns the master's node record, which the caller needs for the route back.
//
// A master with no published key contributes nothing and is not an error: the
// spec converges as nodes register, and one absent master must not take the
// others' peers with it.
func (b *Broker) masterPeers(ctx context.Context, exit config.ExitConfig, exitNode domain.Node,
	master config.MasterConfig, mtu int) ([]domain.PeerSpec, domain.Node, error) {
	legacyHost, perTunnelHost := domain.MasterTunnelHostIndex(master.Slot)
	masterAddr, err := nthHost(exit.AddressPool, legacyHost)
	if err != nil {
		return nil, domain.Node{}, fmt.Errorf("exit %q: master %q address: %w", exit.Name, master.Name, err)
	}
	var peers []domain.PeerSpec
	masterNode, masterPub, err := b.lookupPubKey(ctx, master.Name)
	if err != nil {
		return nil, domain.Node{}, err
	}
	phase := exit.PerTunnelKeyPhase()
	// Exit-initiated AWG flow: the exit dials the master's pinned address, on the
	// ONE peer whose identity the master actually uses in this phase.
	pinned, pinnedOK, err := b.exitInitiatedAddr(ctx, exit, master, exitNode, masterNode)
	if err != nil {
		return nil, domain.Node{}, err
	}
	legacyEndpoint, perTunnelEndpoint := "", ""
	legacyKeepalive := wg.KeepaliveFor(keepaliveIdentity("master-exit|exit|", exit.Name, master))
	perTunnelKeepalive := wg.KeepaliveFor(keepaliveIdentity("master-exit|exit|per-tunnel|", exit.Name, master))
	if pinnedOK {
		// The exit speaks every few seconds on the flow it opened, so a path filter
		// never sees it idle long enough to forget who started it.
		fast := wg.ExitInitiatedKeepaliveFor(keepaliveIdentity("master-exit|exit|", exit.Name, master))
		if phase.MasterUsesPerTunnelKey() {
			perTunnelEndpoint, perTunnelKeepalive = pinned, fast
		} else {
			legacyEndpoint, legacyKeepalive = pinned, fast
		}
	}

	// Legacy shared-identity peer. Kept in every phase but `on`, so the master always
	// has a working way in until the operator has verified the per-tunnel one.
	if phase.ExitAcceptsLegacyKey() {
		if masterPub == "" {
			b.warnOnce("master-key-unpublished:"+master.Name+"/"+exit.Name, "",
				"master public key not yet registered; rendering exit without master peer",
				"exit", exit.Name, "master", master.Name)
		} else {
			peers = append(peers, domain.PeerSpec{
				Name:      master.Name,
				PublicKey: masterPub,
				// Empty: the master dials the exit. Set: the exit starts the flow.
				Endpoint:   legacyEndpoint,
				AllowedIPs: []string{host32(masterAddr)},
				// Per-tunnel, not the fleet-wide 25: a keepalive is a beacon whose
				// PERIOD joined every tunnel we run into one set for a passive
				// observer. It is a local decision, so the two ends need not agree.
				Keepalive: legacyKeepalive,
				MTU:       mtu,
			})
		}
	}

	// Per-tunnel identity peer (ADR-0030), on its OWN address so it does not contend
	// with the legacy peer for the same /32 in the AllowedIPs trie.
	if phase.ExitAcceptsPerTunnelKey() {
		perTunnelAddr, aerr := nthHost(exit.AddressPool, perTunnelHost)
		if aerr != nil {
			return nil, domain.Node{}, fmt.Errorf("exit %q: per-tunnel master address: %w", exit.Name, aerr)
		}
		perTunnelPub, kerr := b.tunnelPubKey(ctx, master.Name, exit.Name)
		if kerr != nil {
			return nil, domain.Node{}, fmt.Errorf("exit %q: %w", exit.Name, kerr)
		}
		switch {
		case perTunnelPub == "":
			// The master has not published this tunnel's key yet (it publishes after it
			// first sees the exit in its own spec, so this is normal for a pass or two).
			// Refusing to render the phase would be wrong; the legacy peer is still
			// there in dual/switch. In `on` there would be NO peer at all, which is why
			// the rollout requires confirming the key is registered before `on`.
			b.warnOnce("master-tunnel-key-unpublished:"+master.Name+"/"+exit.Name, string(phase),
				"master per-tunnel public key not yet registered; rendering exit without the per-tunnel peer",
				"exit", exit.Name, "master", master.Name, "phase", phase)
		default:
			peers = append(peers, domain.PeerSpec{
				Name:       master.Name + " (per-tunnel)",
				PublicKey:  perTunnelPub,
				Endpoint:   perTunnelEndpoint,
				AllowedIPs: []string{host32(perTunnelAddr)},
				Keepalive:  perTunnelKeepalive,
				MTU:        mtu,
			})
		}
	}

	return peers, masterNode, nil
}

// keepaliveIdentity names one end's keepalive period. The base master keeps the
// identity a one-master fleet has always used; every other master adds its name,
// so two masters do not beacon one exit on the same period.
func keepaliveIdentity(prefix, exit string, master config.MasterConfig) string {
	if master.IsBase() {
		return prefix + exit
	}
	return prefix + exit + "|" + master.Name
}

// exitCarries reports whether master is rendered onto this exit at all. The base
// master always is — that is what the exit has today. Any other master needs an
// exit agent that can take a new peer without restarting awg0 and report every
// peer back (api.WireMasterPeers): below it, one more master would bounce the
// interface the base master's traffic is on, on every such exit at once.
func (b *Broker) exitCarries(exit config.ExitConfig, exitNode domain.Node, master config.MasterConfig) bool {
	if master.IsBase() || exitNode.WireVersion >= api.WireMasterPeers {
		return true
	}
	b.warnOnce("master-waits-for-exit:"+master.Name+"/"+exit.Name, fmt.Sprint(exitNode.WireVersion),
		"master not rendered onto this exit yet: the exit's agent is too old to carry a second master",
		"exit", exit.Name, "master", master.Name, "exit_wire", exitNode.WireVersion, "need_wire", api.WireMasterPeers)
	return false
}

// keyOwners maps every public key the masters present on exit's interface to the
// master that keeps it: the first in manifest order.
//
// The kernel knows a peer by its public key and nothing else. Two masters with
// one key — the second built from a copy of the first's disk, so the shared key
// and every derived per-tunnel key match — would render as two peers on two
// addresses, and the exit agent, which keys its view of the kernel the same way,
// would move the one real peer's allowed-ips back and forth: the healthy master
// loses its return path every other pass. So a key is peered once. The renderer
// of the exit and the renderer of each master both decide from this map, or the
// loser would be handed a tunnel whose peer answers on another master's address.
//
// A one-master fleet has nobody to collide with and reads nothing.
func (b *Broker) keyOwners(ctx context.Context, exit config.ExitConfig, exitNode domain.Node) (map[string]string, error) {
	if len(b.fleet.Masters) < 2 {
		return nil, nil
	}
	phase := exit.PerTunnelKeyPhase()
	owners := make(map[string]string)
	claim := func(key, master string) {
		if _, taken := owners[key]; key != "" && !taken {
			owners[key] = master
		}
	}
	for _, m := range b.fleet.Masters {
		if !b.exitCarries(exit, exitNode, m) {
			continue
		}
		if phase.ExitAcceptsLegacyKey() {
			_, pub, err := b.lookupPubKey(ctx, m.Name)
			if err != nil {
				return nil, err
			}
			claim(pub, m.Name)
		}
		if phase.ExitAcceptsPerTunnelKey() {
			pub, err := b.tunnelPubKey(ctx, m.Name, exit.Name)
			if err != nil {
				return nil, fmt.Errorf("exit %q: %w", exit.Name, err)
			}
			claim(pub, m.Name)
		}
	}
	return owners, nil
}

// ownsKey reports whether master is the one peered on exit under key, and says
// so — once — when an earlier master is.
func (b *Broker) ownsKey(owners map[string]string, exit, master, key string) bool {
	owner, claimed := owners[key]
	if !claimed || owner == master {
		return true
	}
	// The key is part of the once-key, not its detail: in dual and switch a copied
	// master collides twice, and two details taking turns would log on every render.
	b.errorOnce("duplicate-master-key:"+exit+"/"+owner+"/"+master+"/"+key, "",
		"two masters present the same WireGuard key; the later one is not peered",
		"exit", exit, "peered", owner, "not_peered", master, "public_key", key)
	return false
}

// peeredOn reports whether the exit holds a peer for the key master dials it with
// in the exit's current phase. A key not published yet is not a refusal: the peer
// appears when it is.
func (b *Broker) peeredOn(ctx context.Context, exit config.ExitConfig, exitNode domain.Node,
	master config.MasterConfig, masterNode domain.Node) (bool, error) {
	owners, err := b.keyOwners(ctx, exit, exitNode)
	if err != nil || len(owners) == 0 {
		return true, err
	}
	key, err := b.masterTunnelKey(ctx, exit, master, masterNode)
	if err != nil {
		return false, fmt.Errorf("exit %q: %w", exit.Name, err)
	}
	return b.ownsKey(owners, exit.Name, master.Name, key), nil
}

// refuseAnotherMastersKey returns an error when nodeID is a manifest master and
// another manifest master already holds publicKey in the slot keyOf reads. The
// render would leave the later of the two without a peer (see keyOwners); told at
// registration, the operator learns it from the node that has the problem.
func (b *Broker) refuseAnotherMastersKey(ctx context.Context, nodeID, publicKey, kind string,
	keyOf func(ctx context.Context, master string) (string, error)) error {
	if _, ok := b.findMaster(nodeID); !ok {
		return nil
	}
	for _, m := range b.fleet.Masters {
		if m.Name == nodeID {
			continue
		}
		held, err := keyOf(ctx, m.Name)
		if err != nil {
			return fmt.Errorf("checking the %s key of %q against master %q: %w", kind, nodeID, m.Name, err)
		}
		if held == publicKey {
			return fmt.Errorf("%q published the %s WireGuard public key master %q already holds: "+
				"two masters with one key cannot share an exit — generate a new key on %q (a copied disk carries the other master's)",
				nodeID, kind, m.Name, nodeID)
		}
	}
	return nil
}
