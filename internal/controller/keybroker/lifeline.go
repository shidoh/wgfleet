package keybroker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
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
// operator did not ask for a lifeline, or the agent is too old to own one. It is
// never a failure in disguise — an empty lifeline interface is structurally valid
// and would be applied happily, locking every user out of the reserve path on the
// one day they reach for it.
//
// The two failures are graded, because their blast radii are not the same size:
//
//   - not being able to find out AT ALL — an unreadable store — returns an error,
//     which fails this exit's whole spec render and leaves the node on its
//     last-good config, peers and all.
//   - ONE credential that cannot be projected is skipped and warned about once
//     (see LifelinePeersOf). Failing the render over it would stop nftables,
//     routing, the exit's own AWG server and its egress from converging because a
//     single person's reserve peer could not be computed.
func (b *Broker) lifelineSpec(ctx context.Context, exit config.ExitConfig, exitNode domain.Node) (*domain.LifelineSpec, error) {
	if !exit.LifelineEnabled() {
		return nil, nil
	}
	master, ok := b.fleet.BaseMaster()
	if !ok {
		b.warnOnce("lifeline-no-master:"+exit.Name, "none",
			"lifeline not rendered: the fleet has no master whose clients it would carry",
			"exit", exit.Name)
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
	peers, skipped := domain.LifelinePeersOf(clients, masterPool, lifelinePool, exit.Name)
	for _, s := range skipped {
		// One credential's blast radius is one credential. Failing here would fail
		// the exit's whole NodeSpec, and the agent refuses a spec entire — so an
		// address left outside the master pool by an operator narrowing the client
		// pool would stop nftables, routing, the exit's own AWG server and its
		// egress from converging, over one person's reserve peer. That is the
		// trade spec.go argues out for ClientWG and ClientVLESS, and it applies
		// here for the same reason. Keyed per exit AND credential so each affected
		// credential is named once, and again if its reason changes.
		b.warnOnce("lifeline-unprojectable-credential:"+exit.Name+"/"+s.ID, s.Reason.Error(),
			"lifeline peer skipped: this credential cannot be projected onto the reserve interface; every other client is unaffected",
			"exit", exit.Name, "credential", s.Name, "credential_id", s.ID, "reason", s.Reason)
	}

	return &domain.LifelineSpec{
		ClientWGSpec: domain.ClientWGSpec{
			ListenPort:    l.ListenPort,
			AddressPool:   l.AddressPool,
			ServerAddress: gateway.String(),
			MTU:           lifelineMTU(exit),
			DNS:           b.lifelineResolvers(exit, gateway),
			Keepalive:     master.ClientAWG.Keepalive,
			AllowedIPs:    lifelineAllowedIPs(exit),
			AWG:           lifelineAWG(exit, master, exitNode, b.awg3Key),
			// Exits carry the AmneziaWG kernel module by construction (it is what
			// their own WGServer runs on), so there is no userspace case to resolve.
			Backend: domain.ClientWGBackendKernel,
			Clients: peers,
		},
		Egress: l.ResolvedEgress(),
	}, nil
}

// lifelineAllowedIPs is what a reserve config routes into the tunnel: the plain
// default route, unless the operator overrode it per exit.
//
// It used to copy the master's list, on the argument that the reserve profile is
// the same credential and should make the same routing decision. Measured on a
// real client, that argument costs the profile its ability to connect at all.
//
// The master's list is a SPLIT one whenever `client_awg.exclude_from_tunnel` is
// set: 0.0.0.0/0 expanded into ~44 prefixes with the private ranges cut out. A
// client that brings such a config up with wg-quick/awg-quick gets one plain
// route per prefix in the MAIN table, and two things then go wrong that a single
// "0.0.0.0/0" avoids entirely:
//
//   - The tunnel's own endpoint is swallowed. wg-quick installs its fwmark and
//     `suppress_prefixlength 0` rules ONLY when it sees a literal /0; with a split
//     list it does not, so the route covering the server's own address (192.128.0.0/11
//     for a 192.144.x endpoint, 193.0.0.0/8 for a 193.x one) points at the tunnel
//     device. The handshake completes — it goes out before the routes are added —
//     and then every packet loops. Measured: DNS times out, nothing loads, and the
//     interface counts gigabytes sent in seconds.
//   - Any prefix the client already has a route for aborts the bring-up. A machine
//     on the management overlay already owns 172.29.0.0/16, so `ip route add` returns
//     "File exists", wg-quick rolls the whole thing back, and there is no interface at
//     all. Measured on a live client, on the main profile and the reserve one alike.
//
// With 0.0.0.0/0 neither happens: wg-quick puts the single default in its own
// table behind the fwmark rules, adds nothing to the main table, and the client's
// own specific routes — its LAN, its overlay — keep winning because
// suppress_prefixlength only hides the main table's DEFAULT route. The reserve
// profile is a fallback that must come up on an unfamiliar machine on the worst
// day; "everything through the tunnel" is both the simplest thing to get right and
// what a fallback should do anyway (it already has no geo rules, no balancing and
// no failover — see the ADR).
//
// An operator who does need a split list on the reserve door writes it out in
// `lifeline.allowed_ips`. IPv6 prefixes are dropped from it by FAMILY: the
// lifeline spec carries no IPv6 prefix for the interface to answer from, so a v6
// route here is the black hole an earlier finding is about. An entry that does not parse
// is left alone for validation to complain about.
func lifelineAllowedIPs(exit config.ExitConfig) []string {
	if len(exit.Lifeline.AllowedIPs) == 0 {
		return []string{"0.0.0.0/0"}
	}
	out := make([]string, 0, len(exit.Lifeline.AllowedIPs))
	for _, a := range exit.Lifeline.AllowedIPs {
		if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Is6() {
			continue
		}
		out = append(out, a)
	}
	return out
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

// LifelineExits names every exit the manifest gives a reserve client-facing
// interface, in manifest order. It answers from the manifest alone: this is the
// set of doors the operator DECLARED, and whether each one is currently usable is
// a separate question (clientcfg.ListLifelineExits asks it) — collapsing the two
// here would drop a misconfigured exit off the console instead of showing the
// operator what to fix.
func (b *Broker) LifelineExits(context.Context) ([]string, error) {
	var out []string
	for _, e := range b.fleet.Exits {
		if e.LifelineEnabled() {
			out = append(out, e.Name)
		}
	}
	return out, nil
}

// LifelineMaster names the master whose clients every reserve interface carries:
// the base master. An exit's lifeline projects one master's credentials into one
// pool, and two masters' clients at the same pool offset would land on one
// address there. "" when no master holds slot 0.
func (b *Broker) LifelineMaster(context.Context) (string, error) {
	base, ok := b.fleet.BaseMaster()
	if !ok {
		return "", nil
	}
	return base.Name, nil
}

// ExitEndpointHost resolves the address a client dials for one exit's lifeline.
//
// It is the SAME resolution the master↔exit tunnel uses (broker.go, renderMasterSpec)
// — declared public_ip, then the bootstrap ssh.host, then the address the node
// registered — and deliberately so: it is one physical endpoint on one node, and
// two answers would mean the tunnel comes up while the reserve config points
// somewhere else. Names are skipped rather than returned (firstIPLiteral), because
// this address also feeds the exit's own kernel-level guards.
//
// This is where the lifeline parts company with the master's EndpointHost, which
// refuses ssh.host outright: for a master that address is typically the management
// overlay and must never reach an end user. An exit's is not — an exit is
// hand-declared by the address it is reached at, and the tunnel already dials it.
//
// "" is a valid answer meaning "the fleet knows no dialable address for this exit";
// a node the store has never seen is likewise not an error, since an exit may be
// declared long before it registers.
func (b *Broker) ExitEndpointHost(ctx context.Context, exitID string) (string, error) {
	exit, ok := b.findExit(exitID)
	if !ok {
		return "", fmt.Errorf("keybroker: exit %q not found in fleet manifest", exitID)
	}
	node, err := b.store.GetNode(ctx, exitID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("keybroker: reading %q from the inventory: %w", exitID, err)
	}
	if addr, found := firstIPLiteral(exit.PublicIP, exit.SSH.Host, node.PublicIP); found {
		return addr.String(), nil
	}
	return "", nil
}
