package keybroker

import (
	"context"
	"fmt"
	"time"

	"github.com/shidoh/wgfleet/internal/api"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
)

// Client-facing WireGuard credentials: the controller-side half of the master's
// client interface. The broker mints them (keys + address), the store
// keeps them, and clientWGSpec projects them onto the node's desired state.

// errBadClientName is the single rule for every path that names a credential.
// The name is written verbatim as a comment into the live interface config, so a
// newline in it appends a peer of somebody else's choosing — and until this call
// existed, the broker checked only the LENGTH while its comment claimed it
// mirrored the charset rule. domain.ValidClientName is that rule; there is now
// one copy of it on the write path.
var errBadClientName = fmt.Errorf("keybroker: client name must be 1-%d characters of letters, digits, dot, dash or underscore", domain.MaxClientNameLen)

// mintWGClient resolves a fresh client-facing WireGuard credential for a master
// without storing it.
//
// The split between minting and storing is deliberate and load-bearing. The
// keypair and the address are the only non-deterministic parts of issuing, and
// they are resolved HERE, before the store write, so that the write itself is a
// plain record of a decision already made. Under multi-master (ADR-0027) that
// write replicates through raft and every replica applies it; had the store call
// been "generate a key and take a free address", each replica would have arrived
// at a different answer and the fleet's view of its own clients would diverge.
func (b *Broker) mintWGClient(ctx context.Context, masterID, name string) (domain.WGClient, error) {
	if !domain.ValidClientName(name) {
		return domain.WGClient{}, errBadClientName
	}
	master, ok := b.masterConfig(masterID)
	if !ok {
		// Wrap ErrNotFound so the web layer reports "master not registered" the same
		// way it does for a VLESS credential, instead of an opaque broker error.
		return domain.WGClient{}, fmt.Errorf("keybroker: %q is not a configured master: %w", masterID, store.ErrNotFound)
	}
	pool := master.ClientAWG.AddressPool
	if pool == "" {
		return domain.WGClient{}, fmt.Errorf("keybroker: master %q has no client_awg.address_pool", masterID)
	}

	// Read the addresses already spoken for. A concurrent issue could in principle
	// pick the same one; the store's UNIQUE(master_id, address) turns that into an
	// error rather than two clients sharing an address, which is the failure mode
	// worth being strict about.
	existing, err := b.store.ListWGClients(ctx, masterID)
	if err != nil {
		return domain.WGClient{}, err
	}
	taken := make([]string, 0, len(existing))
	for _, c := range existing {
		taken = append(taken, c.Address)
	}
	serverAddr, err := masterClientAddress(pool)
	if err != nil {
		return domain.WGClient{}, err
	}
	// The master's synthetic client holds the top of the pool and must never be
	// issued to a real one: two peers on the same address is exactly the collision
	// the store's UNIQUE(master_id, address) exists to prevent, arrived at from the
	// direction the store cannot see. A pool too small to seat it returns an error
	// there, which is deliberately NOT fatal here — a tiny pool should still be able
	// to issue clients, it simply gets no path measurement.
	reserved := []string{serverAddr}
	if synth, serr := domain.SyntheticClientAddress(pool); serr == nil {
		reserved = append(reserved, synth)
	}
	address, err := domain.AllocateClientAddress(pool, reserved, taken)
	if err != nil {
		return domain.WGClient{}, err
	}

	kp, err := wg.GenerateKeyPair()
	if err != nil {
		return domain.WGClient{}, fmt.Errorf("keybroker: mint client keypair: %w", err)
	}
	psk, err := wg.GeneratePresharedKey()
	if err != nil {
		return domain.WGClient{}, fmt.Errorf("keybroker: mint client preshared key: %w", err)
	}

	return domain.WGClient{
		ID:           randomUUID(),
		Name:         name,
		Address:      address,
		PublicKey:    kp.PublicKey,
		PrivateKey:   kp.PrivateKey,
		PresharedKey: psk,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}, nil
}

// IssueWGClient mints a client-facing WireGuard credential for a master and
// persists it.
func (b *Broker) IssueWGClient(ctx context.Context, masterID, name string) (domain.WGClient, error) {
	c, err := b.mintWGClient(ctx, masterID, name)
	if err != nil {
		return domain.WGClient{}, err
	}
	if err := b.store.AddWGClient(ctx, masterID, c); err != nil {
		return domain.WGClient{}, err
	}
	b.log.Info("client WG credential issued", "master", masterID, "client", name, "address", c.Address)
	return c, nil
}

// ListWGClients returns a master's issued client-facing credentials. The records
// carry private keys (the controller renders the configs), so callers that build
// node-bound data must project them through domain.PeersOf.
func (b *Broker) ListWGClients(ctx context.Context, masterID string) ([]domain.WGClient, error) {
	return b.store.ListWGClients(ctx, masterID)
}

// SetWGClientEnabled mutes or unmutes a credential. A muted client leaves the
// interface on the next reconcile while its config stays valid.
func (b *Broker) SetWGClientEnabled(ctx context.Context, masterID, clientID string, enabled bool) error {
	return b.store.SetWGClientEnabled(ctx, masterID, clientID, enabled)
}

// RenameWGClient changes the operator-facing label only.
func (b *Broker) RenameWGClient(ctx context.Context, masterID, clientID, name string) error {
	if !domain.ValidClientName(name) {
		return errBadClientName
	}
	return b.store.RenameWGClient(ctx, masterID, clientID, name)
}

// RevokeWGClient removes a credential outright; the next spec render drops its
// peer from the interface.
func (b *Broker) RevokeWGClient(ctx context.Context, masterID, clientID string) error {
	return b.store.RemoveWGClient(ctx, masterID, clientID)
}

// clientWGSpec resolves a master's client-facing AmneziaWG interface.
//
// The obfuscation and the MTU are NOT re-derived here: they are the same values
// the client-facing WGServerSpec already carries.
// An ABSENT block is a command, not a shrug: the agent reads it as "no client
// interface" and brings ours down. So nil may only ever express a DECISION — the
// master has no client_awg.address_pool, or its agent is too old to own the
// interface. Every failure to find out returns an
// error instead, which fails this master's spec render, fails PullSpec, and leaves
// the node on its last-good config: unknown means leave it alone.
func (b *Broker) clientWGSpec(ctx context.Context, master config.MasterConfig, server domain.WGServerSpec) (*domain.ClientWGSpec, error) {
	if !master.ClientAWGEnabled() {
		return nil, nil
	}
	node, err := b.store.GetNode(ctx, master.Name)
	if err != nil {
		return nil, fmt.Errorf("client WG interface: cannot read the master's registration: %w", err)
	}
	if node.WireVersion < api.WireClientWG {
		// A DECISION, not a failure: the agent predates wire v8 and would drop this
		// block anyway. Rendering nothing lets the rest of the master converge, and
		// the operator sees why.
		b.log.Warn("client WG interface not rendered: agent is too old to own the client interface; upgrade it",
			"master", master.Name, "agent_wire", node.WireVersion, "need_wire", api.WireClientWG)
		return nil, nil
	}
	serverAddr, err := masterClientAddress(master.ClientAWG.AddressPool)
	if err != nil {
		return nil, fmt.Errorf("client WG interface: bad client pool %q: %w", master.ClientAWG.AddressPool, err)
	}
	clients, err := b.store.ListWGClients(ctx, master.Name)
	if err != nil {
		// NOT parity with clientVLESSSpec, deliberately: an empty VLESS inbound
		// authenticates nobody on a transport most people are not using, while an
		// empty client interface drops EVERY user at once. A transient store error
		// must not be able to do that, so it fails the render and the node keeps its
		// last-good interface with all its peers.
		return nil, fmt.Errorf("client WG interface: listing credentials: %w", err)
	}
	// The IPv6 block, rendered as one thing or not at all.
	//
	// "::/0" tells the client to stop preferring its own IPv6 and send it here;
	// IPv6Prefix is what lets the master address itself in v6 and answer with an
	// ICMPv6 rejection. Either alone is worse than neither: the route without the
	// answer abandons a working path for one that drops silently, and that failure
	// wears the costume of an MTU fault. So the wire gate covers BOTH — an agent that
	// would drop the prefix is not handed the route either, and simply keeps today's
	// IPv4-only behaviour.
	allowedIPs := master.ClientAWGAllowedIPs()
	ipv6Prefix := ""
	if master.ClientAWG.IPv6 == config.ClientIPv6Block {
		if node.WireVersion >= api.WireClientIPv6 {
			prefix, perr := wg.ClientULAFor(master.ClientAWG.AddressPool)
			if perr != nil {
				return nil, fmt.Errorf("client WG interface: deriving the IPv6 prefix: %w", perr)
			}
			ipv6Prefix = prefix.String()
			allowedIPs = append(append([]string(nil), allowedIPs...), "::/0")
		} else {
			b.log.Warn("client IPv6 block not rendered: agent is too old to answer IPv6",
				"master", master.Name, "agent_wire", node.WireVersion, "need_wire", api.WireClientIPv6)
		}
	}

	mtu := master.ClientAWGMTU()
	if mtu == 0 {
		mtu = server.MTU
	}
	if master.ClientAWG3() == config.ClientAWG3Full && node.WireVersion < api.WireAWG3TrackB {
		// The configs handed to devices come from this controller and would carry
		// the trailers; an older agent would bring wg0 up without them. Hold the
		// whole leg at timers until the agent catches up — no device notices.
		b.warnOnce("client-awg3-held:"+master.Name, fmt.Sprint(node.WireVersion),
			"client_awg.awg3 is full, but this master's agent is too old for it; the client interface stays at timers until it is upgraded",
			"master", master.Name, "agent_wire", node.WireVersion, "need_wire", api.WireAWG3TrackB)
		master.ClientAWG.AWG3 = string(config.ClientAWG3Timers)
	}
	awg := clientLegAWG(master, server, b.awg3Key)
	return &domain.ClientWGSpec{
		ListenPort:    master.ClientListenPort(),
		AddressPool:   master.ClientAWG.AddressPool,
		ServerAddress: serverAddr,
		MTU:           mtu,
		DNS:           b.clientResolvers(ctx, master),
		Keepalive:     master.ClientAWG.Keepalive,
		AllowedIPs:    allowedIPs,
		IPv6Prefix:    ipv6Prefix,
		AWG:           awg,
		Backend:       master.ClientAWGBackend(),
		Clients:       domain.PeersOf(clients),
	}, nil
}

// masterClientAddress returns the master's own address inside its client pool:
// the first host. Configured clients carry it as their gateway, so it must not
// move.
func masterClientAddress(pool string) (string, error) {
	addr, err := nthHost(pool, 1)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

// masterConfig looks up a master's manifest entry by name.
func (b *Broker) masterConfig(name string) (config.MasterConfig, bool) {
	for _, m := range b.fleet.Masters {
		if m.Name == name {
			return m, true
		}
	}
	return config.MasterConfig{}, false
}

// clientLegAWG resolves the obfuscation for the client interface: the 2.0 params
// derived for the client-facing WGServer, plus whatever half of AmneziaWG 3.x the
// operator asked for.
//
// The 3.x half is applied to a COPY, never to server.AWG, so the operator's 3.x
// choice stays confined to the client leg and cannot leak into anything else
// built from that struct.
//
// Both ends of this tunnel derive from the same seed, so the shared half the
// client's .conf carries is byte-identical to the interface's by construction;
// only the local decoy differs per end, which AmneziaWG allows and we want. The
// 3.x timers set here are the exception: they are per-end, and the client-side
// renderers drop them (wg.ClientAWGParams), so "timers" changes this interface
// and no client config at all.
func clientLegAWG(master config.MasterConfig, server domain.WGServerSpec, awg3Key string) *domain.AWGParams {
	if server.AWG == nil {
		return nil
	}
	mode := master.ClientAWG3()
	if mode == config.ClientAWG3Off {
		return server.AWG
	}
	// The seed must be the one this leg's 2.0 params were derived from, or the two
	// halves of one interface would disagree.
	seed := wg.TunnelSeed(master.Name, "clients", awgSalt)
	p := wg.WithAWG3Timers(*server.AWG, seed)
	if mode == config.ClientAWG3Full {
		p = wg.WithAWG3HeaderProtection(p, seed, awg3Key)
	}
	return &p
}
