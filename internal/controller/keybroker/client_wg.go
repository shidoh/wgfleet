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

// Client-facing WireGuard credentials: the controller-side half of the leg that
// used to belong to wg-easy. The broker mints them (keys + address), the store
// keeps them, and clientWGSpec projects them onto the node's desired state.

// errBadClientName is the single rule for every path that names a credential.
// The name is written verbatim as a comment into the live interface config, so a
// newline in it appends a peer of somebody else's choosing — and until this call
// existed, the broker checked only the LENGTH while its comment claimed it
// mirrored the charset rule. domain.ValidClientName is that rule; there is now
// one copy of it on the write path.
var errBadClientName = fmt.Errorf("keybroker: client name must be 1-%d characters of letters, digits, dot, dash or underscore", domain.MaxClientNameLen)

// IssueWGClient mints a client-facing WireGuard credential for a master and
// persists it.
//
// The split between minting and storing is deliberate and load-bearing. The
// keypair and the address are the only non-deterministic parts of issuing, and
// they are resolved HERE, before the store write, so that the write itself is a
// plain record of a decision already made. Under multi-master (ADR-0027) that
// write replicates through raft and every replica applies it; had the store call
// been "generate a key and take a free address", each replica would have arrived
// at a different answer and the fleet's view of its own clients would diverge.
func (b *Broker) IssueWGClient(ctx context.Context, masterID, name string) (domain.WGClient, error) {
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
	address, err := domain.AllocateClientAddress(pool, []string{serverAddr}, taken)
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

	c := domain.WGClient{
		ID:           randomUUID(),
		Name:         name,
		Address:      address,
		PublicKey:    kp.PublicKey,
		PrivateKey:   kp.PrivateKey,
		PresharedKey: psk,
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}
	if err := b.store.AddWGClient(ctx, masterID, c); err != nil {
		return domain.WGClient{}, err
	}
	b.log.Info("client WG credential issued", "master", masterID, "client", name, "address", address)
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

// clientWGSpec resolves a master's client-facing AmneziaWG interface, or nil when
// the operator has not handed it over (wg-easy still owns the leg).
//
// The obfuscation and the MTU are NOT re-derived here: they are the same values
// the client-facing WGServerSpec already carries, so a client configured before
// the handover keeps working after it. That is the whole point of the transparent
// migration — the server implementation changes underneath, the wire does not.
// An ABSENT block is a command, not a shrug: the agent reads it as "the leg was
// handed back", brings our interface down and lets compose restore wg-easy. So
// nil may only ever express a DECISION the operator made — the knob is off, or the
// agent is too old to own the leg. Every failure to find out returns an error
// instead, which fails this master's spec render, fails PullSpec, and leaves the
// node on its last-good config: unknown means leave it alone.
func (b *Broker) clientWGSpec(ctx context.Context, master config.MasterConfig, server domain.WGServerSpec) (*domain.ClientWGSpec, error) {
	if !master.ClientAWGManaged() {
		return nil, nil
	}
	node, err := b.store.GetNode(ctx, master.Name)
	if err != nil {
		return nil, fmt.Errorf("client WG interface: cannot read the master's registration: %w", err)
	}
	if node.WireVersion < api.WireClientWG {
		// A DECISION, not a failure: the agent predates wire v8, so it drops this
		// block anyway and keeps wg-easy serving the client leg. Rendering nothing is
		// the fail-safe half of that gate — the master converges exactly as before,
		// and the operator sees why.
		b.log.Warn("client WG interface not rendered: agent is too old to own the client leg",
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
	mtu := master.ClientAWGMTU()
	if mtu == 0 {
		mtu = server.MTU
	}
	awg := clientLegAWG(master, server, b.awg3Key)
	return &domain.ClientWGSpec{
		ListenPort:    master.ClientListenPort(),
		AddressPool:   master.ClientAWG.AddressPool,
		ServerAddress: serverAddr,
		MTU:           mtu,
		DNS:           b.clientResolvers(ctx, master),
		Keepalive:     master.ClientAWG.Keepalive,
		AllowedIPs:    master.ClientAWGAllowedIPs(),
		AWG:           awg,
		Backend:       master.ClientAWGBackend(),
		Clients:       domain.PeersOf(clients),
	}, nil
}

// masterClientAddress returns the master's own address inside its client pool:
// the first host, matching what wg-easy hands the interface today so the handover
// does not move the gateway address out from under configured clients.
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

// clientLegAWG resolves the obfuscation for the MANAGED client interface: the
// same 2.0 params wg-easy served, plus whatever half of AmneziaWG 3.x the
// operator asked for.
//
// The 3.x half is applied to a COPY, never to server.AWG. On a master that struct
// is read by the wg-easy planners and by nothing else, and wg-easy's schema has no
// column for a single 3.0 parameter — so leaking them there would have the planner
// write a partial set into its database on every reconcile pass. The client leg's
// generation and wg-easy's are simply different questions.
//
// Both ends of this tunnel derive from the same seed, so the shared half the
// client's .conf carries is byte-identical to the interface's by construction;
// only the local decoy differs per end, which AmneziaWG allows and we want.
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
