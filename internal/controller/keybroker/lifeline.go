package keybroker

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// The lifeline: a reserve client-facing AmneziaWG interface on an exit, carrying
// the SAME client population as the master's own client leg.
//
// It exists for product boundary 3 — the fleet survives its own blocking rather
// than merely reporting it. The master is a single, publicly-dialed address and
// therefore the most blockable thing we run; when it goes, every client goes with
// it, however healthy the exits are. The lifeline is the second door: same
// credentials, a different node, a different port, a different pool.
//
// It is rendered here rather than reusing clientWGSpec because three things
// differ, and each of them is load-bearing:
//
//   - the pool. A client that ever holds both configs must not see the same
//     address twice, so the lifeline shifts the master's pool by host offset
//     (domain.LifelineAddress) instead of allocating anew — no second allocator,
//     no second piece of state, and a peer that is reproducible from the
//     master-side record alone.
//   - the preshared keys. Handing an exit the master's real PSKs would make every
//     exit able to impersonate the master's client interface; the lifeline derives
//     a per-exit key instead (domain.LifelinePSK).
//   - egress. The master forwards into mihomo; an exit releases traffic itself, so
//     the lifeline carries its own egress choice.

// lifelineSpec renders the exit's reserve client-facing interface, or nil when
// the exit has none.
//
// nil is a DECISION here, exactly as it is for the master's client leg: the
// operator did not ask for a lifeline, or the agent is too old to own one. Every
// failure to find out — an unreadable store, a credential that cannot be
// projected — returns an error instead, which fails this exit's whole spec render
// and leaves the node on its last-good config. An empty lifeline interface is
// structurally valid and would be applied happily, locking every user out of the
// reserve path on the one day they reach for it.
func (b *Broker) lifelineSpec(ctx context.Context, exit config.ExitConfig, exitNode domain.Node) (*domain.LifelineSpec, error) {
	if !exit.LifelineEnabled() {
		return nil, nil
	}
	master, ok := b.primaryMaster()
	if !ok {
		b.warnOnce("lifeline-no-master:"+exit.Name, "none",
			"lifeline not rendered: the fleet has no master whose clients it would carry",
			"exit", exit.Name)
		return nil, nil
	}
	if !master.ClientAWGManaged() {
		// config.validateLifeline refuses this pairing at startup, so reaching it
		// means the manifest was assembled in code (tests, a future caller). The
		// controller cannot project credentials it does not own, and inventing an
		// empty interface would be the "locks everyone out" failure above.
		b.warnOnce("lifeline-master-unmanaged:"+exit.Name, master.Name,
			"lifeline not rendered: the master's client interface is not controller-managed",
			"exit", exit.Name, "master", master.Name)
		return nil, nil
	}
	if exitNode.WireVersion < api.WireLifeline {
		// Same shape as the client leg's wire gate: an agent below v11 drops the
		// block, so rendering it would open a firewall hole (Firewall.LifelinePort)
		// in front of a listener that never comes up. warnOnce because this is a
		// standing condition an operator has to go and fix, and specs render every
		// ~30s per node.
		b.warnOnce("lifeline-agent-too-old:"+exit.Name, fmt.Sprint(exitNode.WireVersion),
			"lifeline not rendered: agent is too old to own a reserve client interface",
			"exit", exit.Name, "agent_wire", exitNode.WireVersion, "need_wire", api.WireLifeline)
		return nil, nil
	}

	l := exit.Lifeline
	masterPool, err := netip.ParsePrefix(master.ClientAWG.AddressPool)
	if err != nil {
		return nil, fmt.Errorf("lifeline on %q: bad master client pool %q: %w", exit.Name, master.ClientAWG.AddressPool, err)
	}
	lifelinePool, err := netip.ParsePrefix(l.AddressPool)
	if err != nil {
		return nil, fmt.Errorf("lifeline on %q: bad address pool %q: %w", exit.Name, l.AddressPool, err)
	}
	// The gateway: the first host of the lifeline pool, mirroring what the master
	// takes in its own client pool, so a client moving between the two doors finds
	// the same shape on both.
	gateway, err := nthHost(l.AddressPool, exitHostIndex)
	if err != nil {
		return nil, fmt.Errorf("lifeline on %q: %w", exit.Name, err)
	}

	clients, err := b.store.ListWGClients(ctx, master.Name)
	if err != nil {
		return nil, fmt.Errorf("lifeline on %q: listing credentials: %w", exit.Name, err)
	}
	// exit.Name is the exit's node id — the manifest name and the store id are the
	// same string throughout the broker (see lookupPubKey(ctx, exit.Name)), and the
	// PSK derivation is what makes one exit's lifeline keys useless on another, so
	// it must be THIS exit's identity and nothing else.
	peers, err := domain.LifelinePeersOf(clients, masterPool, lifelinePool, exit.Name)
	if err != nil {
		return nil, fmt.Errorf("lifeline on %q: %w", exit.Name, err)
	}

	return &domain.LifelineSpec{
		ClientWGSpec: domain.ClientWGSpec{
			ListenPort:    l.ListenPort,
			AddressPool:   l.AddressPool,
			ServerAddress: gateway.String(),
			MTU:           lifelineMTU(exit),
			DNS:           b.lifelineResolvers(exit, gateway),
			// The lifeline serves the SAME client configs as the master's interface,
			// so what those configs route into the tunnel is the master's decision,
			// not a second one to keep in sync.
			Keepalive:  master.ClientAWG.Keepalive,
			AllowedIPs: master.ClientAWGAllowedIPs(),
			AWG:        lifelineAWG(exit, master, exitNode, b.awg3Key),
			// Exits carry the AmneziaWG kernel module by construction (it is what
			// their own WGServer runs on), so there is no userspace case to resolve.
			Backend: domain.ClientWGBackendKernel,
			Clients: peers,
		},
		Egress: l.ResolvedEgress(),
	}, nil
}

// lifelineResolvers picks what the lifeline's client configs point at: the
// operator's list when set, else the exit's own blocky on the lifeline gateway.
//
// There is no third option and no inheriting the master's resolvers, which is the
// whole point — the master is by definition the thing this path exists to work
// around, so a DNS list that goes through it makes the reserve interface come up
// and resolve nothing. config.validateLifeline requires one of the two at startup.
func (b *Broker) lifelineResolvers(exit config.ExitConfig, gateway netip.Addr) []string {
	if len(exit.Lifeline.DNS) > 0 {
		return append([]string(nil), exit.Lifeline.DNS...)
	}
	if exit.DNSFilter {
		return []string{gateway.String()}
	}
	return nil
}

// lifelineMTU sizes the reserve interface. MTU is computed, not guessed (earlier findings
// ): the lifeline is one AmneziaWG layer over the exit's own physical link,
// which is the same arithmetic the master↔exit tunnel on that link already does.
//
// A WARP-egressing lifeline takes the MINIMUM of that and the wgcf interface MTU
// AS IS — exitWARPMTU is not subtracted from. These are TERMINATING hops, not a
// nested stack (sequential model, ADR-0014): a client packet is decrypted off
// awgl0 down to the bare payload and re-encapsulated afresh into wgcf, so the two
// hops each impose their own independent cap and neither rides inside the other.
// exitWARPMTU is already the payload wgcf carries, so reserving another AWG layer
// against it would subtract the same overhead twice — it would put a default exit
// at 1240, below wg.MinTunnelMTU, for no path that actually costs those bytes.
// clientFacingMTU does the identical thing with the identical helper, and must:
// the lifeline hands out the same client configs the master's interface does.
//
// An operator override wins outright: it is measured, and we are not.
func lifelineMTU(exit config.ExitConfig) int {
	if exit.Lifeline.MTU > 0 {
		return exit.Lifeline.MTU
	}
	mtu := exitTunnelMTU(exit, false) // IPv4: the lifeline pool is IPv4 by validation
	if exit.Lifeline.ResolvedEgress() == domain.EgressWARP {
		mtu = wg.MinMTU(mtu, exitWARPMTU(exit))
	}
	return mtu
}

// lifelineAWG derives the obfuscation for the reserve interface.
//
// Its own seed, not the master↔exit tunnel's: those are two independent paths,
// and one shared profile spanning both would let an observer who fingerprints one
// recognise the other. The 3.x generation, however, follows the MASTER's
// client_awg.awg3 knob rather than the fleet's exit knob — the lifeline hands out
// the same client configs the master's interface does, so a client that speaks
// 3.x there must find 3.x here and one that does not must find neither.
//
// awg3Enabled takes the exit's record alone. This is the controller's half of the
// gate and it can only see wire versions; the exit's kernel-module generation is
// checked by the agent itself on the node, every pass, exactly as it is for the
// master↔exit tunnel. (In practice WireLifeline is already above WireAWG3, so a
// node that reaches this line has passed both — the call stays because the two
// constants are independent and a future wire renumbering must not silently start
// emitting 3.x to an agent that drops it.)
func lifelineAWG(exit config.ExitConfig, master config.MasterConfig, exitNode domain.Node, awg3Key string) *domain.AWGParams {
	seed := wg.TunnelSeed(exit.Name, "lifeline", awgSalt)
	// The exit is the kernel-module end, so its I1-I5 signatures may use the full
	// CPS tag set; the client end derives the same SHARED half from this seed.
	p := wg.DeriveAWGParamsForEnd(seed, "exit-lifeline", true)

	mode := master.ClientAWG3()
	if mode == config.ClientAWG3Off || !awg3Enabled(true, exitNode) {
		return &p
	}
	p = wg.WithAWG3Timers(p, seed)
	if mode == config.ClientAWG3Full {
		p = wg.WithAWG3HeaderProtection(p, seed, awg3Key)
	}
	return &p
}
