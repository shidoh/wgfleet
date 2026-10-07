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
	pinned, pinnedOK := b.exitInitiatedAddr(ctx, exit, master, exitNode, masterNode)
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
