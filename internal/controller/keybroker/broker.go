// Package keybroker is the controller's key registry and topology renderer. It
// realizes docs/DESIGN.md principle #2: the controller stores only public keys and
// renders each node's peer list from them — it never holds a private key.
//
// MVP topology (the reference master↔exit mesh): exits run a WG server; the
// master dials each exit. The master's client-facing AmneziaWG server (where
// real VPN clients connect) is configured separately and is not part of this
// fleet-internal peering. A single master fronts all exits on MVP.
package keybroker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
	"github.com/shidoh/wgfleet/internal/xray"
)

// awgSalt seeds the deterministic AmneziaWG parameter derivation. It need not be
// secret — AWG obfuscation resists DPI fingerprinting through non-default,
// per-tunnel parameters, not through secrecy. Versioned so params can be rotated
// fleet-wide by bumping it. (Phase 2: source from a fleet secret.)
const awgSalt = "wgfleet-awg-v1"

// Broker renders NodeSpecs from fleet config plus the inventory/pubkey registry.
type Broker struct {
	store store.Store
	fleet config.FleetSection
	log   *slog.Logger
}

// New constructs a Broker over the given store and fleet manifest.
func New(st store.Store, fleet config.FleetSection, log *slog.Logger) *Broker {
	if log == nil {
		log = slog.Default()
	}
	return &Broker{store: st, fleet: fleet, log: log}
}

// RegisterPublicKey records a node's WireGuard public key in the registry. This
// is the only write the key broker makes; everything else is rendered from it.
func (b *Broker) RegisterPublicKey(ctx context.Context, nodeID, publicKey string) error {
	if publicKey == "" {
		return fmt.Errorf("keybroker: empty public key for %q", nodeID)
	}
	// Validate it is a real 32-byte Curve25519 key BEFORE storing it: this value is
	// later rendered verbatim into peer WireGuard configs as `PublicKey = <value>`.
	// A rogue but CA-authenticated node could otherwise publish a multi-line string
	// that injects extra wg-quick directives (e.g. PostUp) into every peer's
	// awg0.conf, which awg-quick executes — remote config injection on peers.
	if !wg.ValidKey(publicKey) {
		return fmt.Errorf("keybroker: malformed WireGuard public key for %q", nodeID)
	}
	if b.keyUnchanged(ctx, nodeID, publicKey, func(n domain.Node) string { return n.PublicKey }) {
		return nil
	}
	if err := b.store.SetNodePublicKey(ctx, nodeID, publicKey); err != nil {
		return err
	}
	b.log.Info("WireGuard public key registered", "node", nodeID)
	return nil
}

// keyUnchanged reports whether the registry already holds publicKey for nodeID in
// the column read by field.
//
// Agents republish EVERY key they hold on EVERY reconcile pass (~30s each), so
// without this guard the controller rewrote byte-identical rows around the clock:
// constant WAL churn plus an INFO line per key per pass, which is most of the
// control plane's ~59k INFO/day. The dedup lives ABOVE the store seam on purpose —
// under the HA plan (ADR-0027 phase B) writes become replicated raft commands, and
// a no-op write deduped only inside SQLiteStore would still have been replicated.
//
// A lookup error counts as "changed": the write path is authoritative and surfaces
// the real error (ErrNotFound → FailedPrecondition), rather than us swallowing it.
func (b *Broker) keyUnchanged(ctx context.Context, nodeID, publicKey string, field func(domain.Node) string) bool {
	node, err := b.store.GetNode(ctx, nodeID)
	if err != nil {
		return false
	}
	return field(node) == publicKey
}

// RegisterRealityKey records an exit's REALITY x25519 public key (ADR-0025),
// stored separately from the WireGuard key and rendered into the master's vless
// proxy. Validated as a 32-byte Curve25519 key before storing — it is rendered
// verbatim into config (reality-opts.public-key), so a malformed/multi-line value
// from a CA-authenticated-but-rogue node must be rejected here.
func (b *Broker) RegisterRealityKey(ctx context.Context, nodeID, publicKey string) error {
	if publicKey == "" {
		return fmt.Errorf("keybroker: empty reality public key for %q", nodeID)
	}
	if !xray.ValidPublicKey(publicKey) {
		return fmt.Errorf("keybroker: malformed REALITY public key for %q", nodeID)
	}
	if b.keyUnchanged(ctx, nodeID, publicKey, func(n domain.Node) string { return n.RealityPublicKey }) {
		return nil
	}
	if err := b.store.SetNodeRealityKey(ctx, nodeID, publicKey); err != nil {
		return err
	}
	b.log.Info("REALITY public key registered", "node", nodeID)
	return nil
}

// RegisterClientVlessKey records the master's CLIENT-FACING REALITY x25519 public
// key (the client VLESS inbound). It validates the key before the store write so a
// CA-authenticated-but-rogue node cannot inject arbitrary text that later renders
// into a vless:// link (same guard as RegisterRealityKey).
func (b *Broker) RegisterClientVlessKey(ctx context.Context, nodeID, publicKey string) error {
	if publicKey == "" {
		return fmt.Errorf("keybroker: empty client vless public key for %q", nodeID)
	}
	if !xray.ValidPublicKey(publicKey) {
		return fmt.Errorf("keybroker: malformed client vless public key for %q", nodeID)
	}
	if b.keyUnchanged(ctx, nodeID, publicKey, func(n domain.Node) string { return n.ClientVLESSPublicKey }) {
		return nil
	}
	if err := b.store.SetNodeClientVlessKey(ctx, nodeID, publicKey); err != nil {
		return err
	}
	b.log.Info("client VLESS REALITY public key registered", "node", nodeID)
	return nil
}

// RegisterClientWGKey records the master's CLIENT-FACING WireGuard public key —
// the identity of the interface end users dial once the agent owns it. Validated
// as a well-formed WireGuard key before storing: it is rendered verbatim into
// every client config the controller hands out, so a malformed value from a
// CA-authenticated-but-rogue node must be refused here (same guard as the
// REALITY keys above).
func (b *Broker) RegisterClientWGKey(ctx context.Context, nodeID, publicKey string) error {
	if publicKey == "" {
		return fmt.Errorf("keybroker: empty client wg public key for %q", nodeID)
	}
	if !wg.ValidKey(publicKey) {
		return fmt.Errorf("keybroker: malformed client wg public key for %q", nodeID)
	}
	if b.keyUnchanged(ctx, nodeID, publicKey, func(n domain.Node) string { return n.ClientWGPublicKey }) {
		return nil
	}
	if err := b.store.SetNodeClientWGKey(ctx, nodeID, publicKey); err != nil {
		return err
	}
	b.log.Info("client WG public key registered", "node", nodeID)
	return nil
}

// clientVLESSSpec resolves a master's client-facing VLESS+REALITY+XHTTP inbound
// desired state, or nil when the transport is disabled. Camouflage falls back
// per-exit-style (manifest → fleet default → safe built-in); the issued client
// credentials come from the store (UI-managed), and empty_sni defaults ON.
func (b *Broker) clientVLESSSpec(ctx context.Context, master config.MasterConfig) *domain.ClientVLESSServerSpec {
	cv := master.ClientVLESS
	if !cv.Enabled {
		return nil
	}
	sni := firstNonEmpty(cv.SNI, cv.DestDomain, b.fleet.RealityDefaultSNI, DefaultRealitySNI)
	dest := firstNonEmpty(cv.DestHostPort(), b.fleet.RealityDefaultDest, sni+":443")
	clients, err := b.store.ListVLESSClients(ctx, master.Name)
	if err != nil {
		// Render the inbound with no clients rather than failing the whole master
		// spec — the listener still comes up; issuance re-renders it.
		b.log.Warn("listing client vless credentials failed; rendering inbound with none",
			"master", master.Name, "err", err)
		clients = nil
	}
	return &domain.ClientVLESSServerSpec{
		ListenPort:    master.ClientVLESSListenPort(),
		Clients:       clients,
		ServerName:    sni,
		Dest:          dest,
		XHTTPPath:     cv.XHTTPPath,
		XHTTPMode:     xray.DefaultXHTTPMode,
		Fingerprint:   cv.ResolvedFingerprint(),
		Mux:           cv.ResolvedMux(),
		Mode:          cv.Mode,
		AllowEmptySNI: cv.ResolvedEmptySNI(),
		AllowIPv6:     cv.AllowIPv6,
		SocksPort:     domain.ClientVLESSSocksPort,
		Image:         config.ResolveImage(cv.Image, cv.Tag, compose.DefaultXrayImage),
	}
}

// IssueVLESSClient mints a fresh client credential (random UUID + REALITY short-id)
// for the master and persists it. The short-id gives per-client REALITY granularity
// and revocation; neither value is secret (the private key stays on the master).
func (b *Broker) IssueVLESSClient(ctx context.Context, masterID, name string) (domain.VLESSClient, error) {
	c := domain.VLESSClient{Name: name, UUID: randomUUID(), ShortID: randomShortID()}
	if err := b.store.AddVLESSClient(ctx, masterID, c); err != nil {
		return domain.VLESSClient{}, err
	}
	return c, nil
}

// ListVLESSClients returns a master's issued client credentials (UI listing).
func (b *Broker) ListVLESSClients(ctx context.Context, masterID string) ([]domain.VLESSClient, error) {
	return b.store.ListVLESSClients(ctx, masterID)
}

// RevokeVLESSClient removes a master's client credential by name; the next spec
// render drops it from the inbound's clients list.
func (b *Broker) RevokeVLESSClient(ctx context.Context, masterID, name string) error {
	return b.store.RevokeVLESSClient(ctx, masterID, name)
}

// ClientVLESSRouteThrough returns the CIDRs a master's clients should route THROUGH
// the tunnel (config.ClientVLESSConfig.RouteThroughCIDRs). Controller-side routing
// metadata for the subscription / UI — not node desired-state, so it is not on the
// wire. Empty for an unknown master or when none are configured.
func (b *Broker) ClientVLESSRouteThrough(masterID string) []string {
	for _, m := range b.fleet.Masters {
		if m.Name == masterID {
			return append([]string(nil), m.ClientVLESS.RouteThroughCIDRs...)
		}
	}
	return nil
}

// randomUUID returns a random RFC-4122 v4 UUID (the VLESS user id).
func randomUUID() string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// randomShortID returns a random 8-hex-char REALITY short-id.
func randomShortID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// RegisterTunnelKey records ONE of the master's per-tunnel WireGuard public keys
// (ADR-0030). tunnel is the exit node's name; the key is the master's dedicated
// identity for that single master↔exit tunnel.
//
// The tunnel name is checked against the manifest's declared exits before storing.
// It is not a security boundary — the row is written under the CALLING node's ID,
// so a rogue exit publishing tunnel keys only pollutes its own rows, which nothing
// reads — but an unknown name is always either a typo or a stale manifest, and
// silently accumulating dead rows would make the migration harder to reason about.
func (b *Broker) RegisterTunnelKey(ctx context.Context, nodeID, tunnel, publicKey string) error {
	if publicKey == "" {
		return fmt.Errorf("keybroker: empty per-tunnel public key for %q tunnel %q", nodeID, tunnel)
	}
	// Same injection guard as RegisterPublicKey: this value is rendered verbatim as
	// `PublicKey = <value>` into the exit's awg0.conf, which awg-quick executes.
	if !wg.ValidKey(publicKey) {
		return fmt.Errorf("keybroker: malformed per-tunnel WireGuard public key for %q tunnel %q", nodeID, tunnel)
	}
	if _, ok := b.findExit(tunnel); !ok {
		return fmt.Errorf("keybroker: per-tunnel key for unknown exit %q (from %q)", tunnel, nodeID)
	}
	// Same steady-state dedup as the node-level keys (see keyUnchanged): a master
	// republishes one key per exit on every pass, so this is the largest single
	// contributor to the churn.
	if cur, err := b.store.ListNodeTunnelKeys(ctx, nodeID); err == nil && cur[tunnel] == publicKey {
		return nil
	}
	if err := b.store.SetNodeTunnelKey(ctx, nodeID, tunnel, publicKey); err != nil {
		return err
	}
	b.log.Info("per-tunnel WireGuard public key registered", "node", nodeID, "tunnel", tunnel)
	return nil
}

// RenderNodeSpec builds the desired NodeSpec for nodeID from its fleet-config
// entry and the registered public keys of its peers. Peers whose public key is
// not yet registered are skipped (the spec converges as more nodes register),
// and the omission is logged rather than silently swallowed.
func (b *Broker) RenderNodeSpec(ctx context.Context, nodeID string) (domain.NodeSpec, error) {
	// A node flagged for decommission gets a teardown spec — the agent reverses
	// its data plane instead of converging.
	if node, err := b.store.GetNode(ctx, nodeID); err == nil && node.Decommission {
		return domain.NodeSpec{Role: node.Role, Decommission: true}, nil
	}
	spec, hardening, err := b.renderRoleSpec(ctx, nodeID)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	// Host hardening is role-agnostic (it runs on masters and exits alike), so it is
	// resolved here rather than duplicated into both role renderers. The node's own
	// section comes back from the dispatch below, since only that step knows which
	// manifest entry nodeID belongs to.
	spec.Hardening = b.fleet.HardeningFor(hardening)
	return spec, nil
}

// renderRoleSpec dispatches to the role-specific renderer for nodeID, also
// returning that node's manifest hardening section for the caller to resolve.
func (b *Broker) renderRoleSpec(ctx context.Context, nodeID string) (domain.NodeSpec, config.HardeningSection, error) {
	if exit, ok := b.findExit(nodeID); ok {
		spec, err := b.renderExitSpec(ctx, exit)
		return spec, exit.Hardening, err
	}
	if master, ok := b.findMaster(nodeID); ok {
		spec, err := b.renderMasterSpec(ctx, master)
		return spec, master.Hardening, err
	}
	return domain.NodeSpec{}, config.HardeningSection{},
		fmt.Errorf("keybroker: node %q not found in fleet manifest", nodeID)
}

// renderExitSpec builds the spec for an exit: a WG server with the fronting
// master as its sole peer.
func (b *Broker) renderExitSpec(ctx context.Context, exit config.ExitConfig) (domain.NodeSpec, error) {
	exitAddr, err := nthHost(exit.AddressPool, exitHostIndex)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	masterAddr, err := nthHost(exit.AddressPool, masterHostIndex)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	port := exit.WGListenPort()
	egress := domain.EgressMethod(exit.Egress)
	// The exit's own store node carries the operator's live active-transport override.
	exitNode, _ := b.lookupPubKey(ctx, exit.Name)

	// The management overlay (ZeroTier) must be trusted on every exit without the
	// operator hand-listing it: route it DIRECT so client→mgmt traffic (e.g. DNS to
	// blocky on a sibling exit) never gets pulled into WARP, and
	// accept it in the firewall so admin/metrics/controller reach the node over the
	// overlay. Derived from fleet.mgmt_subnet or the nodes' mgmt_addr /32s.
	mgmtCIDRs := b.fleet.MgmtCIDRs()

	// The exit's server carries the master↔exit tunnel. It is AmneziaWG over its
	// own physical link, so its MTU subtracts one AWG-obfuscated layer (sequential
	// model, ADR-0014; an earlier finding). When the operator pins link_mtu (the exit's
	// real path is below 1500), the tunnel drops accordingly so carrier packets fit.
	serverMTU := exitTunnelMTU(exit, exitAddr.Is6())

	// AmneziaWG obfuscation for the master↔exit tunnel: derived deterministically
	// from the tunnel identity so both ends compute the identical shared params
	// (only Jc/Jmin/Jmax may differ; this end uses the defaults).
	var awg *domain.AWGParams
	if master, ok := b.primaryMaster(); ok {
		// Exit is the kernel-module (awg-quick) end of the master↔exit tunnel, so
		// its I1-I5 signatures may use the full CPS tag set including <c>/<t>.
		seed := wg.TunnelSeed(exit.Name, master.Name, awgSalt)
		p := wg.DeriveAWGParamsForEnd(seed, "exit", true)
		// AmneziaWG 3.0, when the operator opted in AND this exit's agent can render
		// it. The SAME decision is taken for the master end below from the same
		// inputs — both ends of one tunnel must agree on the generation or the
		// handshake never completes, so this must never be decided twice differently.
		if awg3Enabled(b.fleet.AWG3For(exit), exitNode) {
			p = wg.WithAWG3(p, seed)
		}
		awg = &p
	}

	spec := domain.NodeSpec{
		Role:        domain.RoleExit,
		Egress:      egress,
		EgressChain: egressChain(exit),
		// Master↔exit transport set (ADR-0025). Defaults to AWG-only. The REALITY
		// server spec (spec.Reality) and the master-side proxies are populated in
		// later phases; until then an exit may only enable TransportAWG.
		EnabledTransports: exit.EnabledTransports(),
		ActiveTransport:   resolveActiveTransport(exit, exitNode),
		WGServer: domain.WGServerSpec{
			ListenPort:  port,
			AddressPool: exit.AddressPool,
			Address:     exitAddr.String(),
			MTU:         serverMTU,
			AWG:         awg,
		},
		// WARP egress rides the exit's own physical link to Cloudflare, whose path
		// MTU can be below 1500. Send the RAW per-exit warp_mtu: >0 pins
		// it, 0 ⇒ the agent auto-probes the path MTU (tracepath) and falls back to
		// wg.DefaultWARPMTU. The controller's own MTU math below uses exitWARPMTU
		// (operator value or the conservative default) since it can't see the probe.
		WARPMTU: exit.WARPMTU,
		// Egress throughput watchdog (ADR-0021): the agent measures real throughput on
		// the active egress and reports it; a sustained collapse fails over to a
		// fallback (if any) and/or the controller auto-suspends the exit from the LB.
		// 0 ⇒ watchdog disabled for this exit (per-exit or fleet override).
		EgressThroughputMinBps:   b.fleet.EgressThroughputFloorKBytes(exit) * 1024,
		EgressThroughputProbeURL: b.fleet.EgressThroughputProbeURL,
		DNS:                      b.renderDNS(ctx, exit),
		Firewall: domain.FirewallSpec{
			ASBlacklist:    exit.Firewall.ASBlacklist,
			Whitelist:      mergeUnique(exit.Firewall.Whitelist, mgmtCIDRs),
			WGPort:         port,
			PublicTCPPorts: append([]int(nil), exit.Firewall.PublicTCPPorts...),
			PublicUDPPorts: append([]int(nil), exit.Firewall.PublicUDPPorts...),
		},
		Exporters: domain.ExportersSpec{Node: true, WG: true, WARP: egress == domain.EgressWARP},
	}

	master, ok := b.primaryMaster()
	if !ok {
		b.log.Warn("exit has no master to peer with", "exit", exit.Name)
		return spec, nil
	}
	masterNode, masterPub := b.lookupPubKey(ctx, master.Name)
	phase := exit.PerTunnelKeyPhase()

	// Legacy shared-identity peer. Kept in every phase but `on`, so the master always
	// has a working way in until the operator has verified the per-tunnel one.
	if phase.ExitAcceptsLegacyKey() {
		if masterPub == "" {
			b.log.Warn("master public key not yet registered; rendering exit without master peer",
				"exit", exit.Name, "master", master.Name)
		} else {
			spec.Peers = append(spec.Peers, domain.PeerSpec{
				Name:       master.Name,
				PublicKey:  masterPub,
				Endpoint:   "", // master dials the exit; exit is the server side
				AllowedIPs: []string{host32(masterAddr)},
				Keepalive:  domain.DefaultKeepaliveSeconds,
				MTU:        serverMTU,
			})
		}
	}

	// Per-tunnel identity peer (ADR-0030), on its OWN address so it does not contend
	// with the legacy peer for the same /32 in the AllowedIPs trie.
	if phase.ExitAcceptsPerTunnelKey() {
		perTunnelAddr, aerr := nthHost(exit.AddressPool, masterPerTunnelHostIndex)
		if aerr != nil {
			return domain.NodeSpec{}, fmt.Errorf("exit %q: per-tunnel master address: %w", exit.Name, aerr)
		}
		perTunnelPub := b.tunnelPubKey(ctx, master.Name, exit.Name)
		switch {
		case perTunnelPub == "":
			// The master has not published this tunnel's key yet (it publishes after it
			// first sees the exit in its own spec, so this is normal for a pass or two).
			// Refusing to render the phase would be wrong; the legacy peer is still
			// there in dual/switch. In `on` there would be NO peer at all, which is why
			// the rollout requires confirming the key is registered before `on`.
			b.log.Warn("master per-tunnel public key not yet registered; rendering exit without the per-tunnel peer",
				"exit", exit.Name, "master", master.Name, "phase", phase)
		default:
			spec.Peers = append(spec.Peers, domain.PeerSpec{
				Name:       master.Name + " (per-tunnel)",
				PublicKey:  perTunnelPub,
				Endpoint:   "",
				AllowedIPs: []string{host32(perTunnelAddr)},
				Keepalive:  domain.DefaultKeepaliveSeconds,
				MTU:        serverMTU,
			})
		}
	}

	// Routing intent: client traffic egresses via WARP, but management and the
	// path back to the master must stay direct (an earlier finding–#5).
	spec.Routing = domain.RoutingSpec{
		MasterIP:    masterNode.PublicIP,
		DirectCIDRs: mergeUnique(b.masterDirectCIDRs(master), mgmtCIDRs),
	}
	if egress == domain.EgressWARP {
		spec.Routing.EgressInterface = "wgcf"
	}

	// REALITY/XHTTP inbound desired state (ADR-0025), set when the exit runs the
	// reality transport. The shared identifiers (UUID/short-id) and camouflage match
	// the master's vless proxy because both call realityFor with the same inputs; the
	// exit generates its own x25519 keypair locally and publishes only the pubkey.
	if spec.HasTransport(domain.TransportRealityXHTTP) {
		rp := b.realityFor(exit, master.Name)
		spec.Reality = &domain.RealityServerSpec{
			ListenPort: rp.Port, UUID: rp.UUID, ShortID: rp.ShortID,
			ServerName: rp.ServerName, Dest: rp.Dest,
			XHTTPPath: rp.Path, XHTTPMode: rp.Mode, Mode: rp.RealityMode,
			AllowEmptySNI: rp.EmptySNI, AllowIPv6: rp.AllowIPv6, Image: rp.Image,
		}
		// Open the reality inbound's TCP port so the master can dial it (the AWG
		// WGPort above is UDP; reality is TCP).
		spec.Firewall.RealityPort = rp.Port
	}
	return spec, nil
}

// renderMasterSpec builds the spec for a master: its client-facing AmneziaWG
// server (WGServer) plus the mihomo data plane (MasterSpec) carrying one
// AmneziaWG WireGuard proxy per registered exit. The master↔exit tunnels live in
// mihomo, not in kernel WG interfaces (ADR-0007).
func (b *Broker) renderMasterSpec(ctx context.Context, master config.MasterConfig) (domain.NodeSpec, error) {
	// Client-facing AmneziaWG interface (wg-easy). Clients are configured
	// out-of-band with the matching shared params (same derivation seed).
	clientSeed := wg.TunnelSeed(master.Name, "clients", awgSalt)
	clientAWG := wg.DeriveAWGParams(clientSeed)
	// The CLIENT end of this tunnel gets its OWN junk/signature profile, distinct
	// from the server interface's (AWG permits Jc/Jmin/Jmax + I1-I5 to differ per
	// end, so they must). Same seed ⇒ identical shared S/H (which clients derive
	// from the interface); a different end label ⇒ different local decoy. kernel=
	// false: clients are userspace (Amnezia), so signatures stay free of <c>/<t>.
	clientPeer := wg.DeriveAWGParamsForEnd(clientSeed, "client", false)
	clientPort := master.ClientListenPort()
	spec := domain.NodeSpec{
		Role: domain.RoleMaster,
		WGServer: domain.WGServerSpec{
			ListenPort:  clientPort,
			AddressPool: master.ClientAWG.AddressPool,
			// Client-facing AWG hop. Sequential model (ADR-0014): the client MTU is
			// the minimum across every hop its payload traverses — client↔master and
			// master↔exit (AWG, 1360) and exit→WARP. With default WARP (1440) the AWG
			// hop binds at 1360; if any exit pins a smaller WARP MTU, the
			// client drops to it so packets never fragment at that exit's egress.
			MTU:            b.clientFacingMTU(),
			AWG:            &clientAWG,
			ClientAWGLocal: &clientPeer.Local,
		},
		// The master now reconciles an input firewall too (drop policy). Trust the
		// mgmt overlay in its whitelist as well (the iifname "zt*" accept already
		// covers ZT inbound; this also allows any non-overlay mgmt sources the
		// operator lists). WGPort opens the client-facing AWG listener.
		Firewall: domain.FirewallSpec{
			WGPort: clientPort,
			// Operator entries first, mgmt CIDRs merged in and never droppable:
			// the overlay is how the control plane reaches this node, so a manifest
			// typo must not be able to lock the controller out. Mirrors the exit.
			Whitelist: mergeUnique(master.Whitelist, b.fleet.MgmtCIDRs()),
			// World-facing TCP services on the master (e.g. the decoy web listener).
			PublicTCPPorts: append([]int(nil), master.PublicTCPPorts...),
			PublicUDPPorts: append([]int(nil), master.PublicUDPPorts...),
		},
		Exporters: domain.ExportersSpec{Node: true, WG: true},
	}

	ms := &domain.MasterSpec{
		Balance:             mihomoStrategy(master.Routing.Balance),
		HealthCheckInterval: int(master.Mihomo.HealthInterval.Seconds()),
		DirectCIDRs:         append([]string(nil), master.Routing.DirectCIDRs...),
		DirectGeo:           append([]string(nil), master.Routing.DirectGeo...),
		SnifferSkip:         append([]string(nil), master.Mihomo.SnifferSkip...),
		RedirPort:           master.Mihomo.RedirPort,
		DashboardURL:        master.Mihomo.DashboardURL,
		DashboardDisabled:   master.Mihomo.DashboardDisabled,
		ClientAdminPorts:    append([]int(nil), master.ClientAdminPorts...),
		Custom:              masterCustomConfig(master),
		MaxFailedTimes:      master.Mihomo.MaxFailedTimes,
	}

	// Route client traffic to the master's OWN public IP DIRECT, exactly as each
	// exit's public IP is handled below. Without it the prerouting DNAT catches
	// client TCP to the master's own address and sends it into mihomo instead of
	// letting it terminate locally: SSH and the admin UIs then hang off the proxy
	// being healthy, and every packet takes a pointless userspace round trip.
	// Found live 2026-07-20 — the DNAT guard list carried all five exits and not
	// the master, because the exit-public-IP fix was never applied to the node
	// that hosts the rule.
	if ip := b.masterPublicIP(ctx, master); ip != "" {
		if addr, err := netip.ParseAddr(ip); err == nil {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			ms.DirectCIDRs = append(ms.DirectCIDRs, netip.PrefixFrom(addr, bits).String())
		} else {
			b.log.Warn("master has unparseable public IP; omitting from DIRECT cidrs",
				"master", master.Name, "public_ip", ip)
		}
	}
	// Tier membership is master-scoped (ADR-0029): the same exit may be primary for
	// one master and reserve for another, so resolve it per master, not per exit.
	reserveExits := make(map[string]struct{}, len(master.Routing.ReserveExits))
	for _, name := range master.Routing.ReserveExits {
		reserveExits[name] = struct{}{}
	}
	if addr, err := nthHost(master.ClientAWG.AddressPool, exitHostIndex); err == nil {
		ms.BindAddress = addr.String() // master's own .1 in the client pool
	}
	if master.MgmtAddr != "" {
		ms.ExternalController = master.MgmtAddr + ":9090" // Clash API on mgmt only
	}
	ms.Compose = b.composeSpec(ctx, master)
	// Client-facing VLESS+REALITY+XHTTP inbound (a DPI-resistant alternative to the
	// client AWG). Its world-facing TCP port opens like any other public service.
	ms.ClientVLESS = b.clientVLESSSpec(ctx, master)
	if ms.ClientVLESS != nil {
		spec.Firewall.PublicTCPPorts = append(spec.Firewall.PublicTCPPorts, ms.ClientVLESS.ListenPort)
	}
	// Client-facing AmneziaWG interface, when the agent owns it instead of wg-easy.
	// It reuses the client-facing WGServer's obfuscation and MTU verbatim so the
	// handover is invisible to already-configured clients; the listener's UDP port
	// is already open via Firewall.WGPort above, which is the same port.
	cwSpec, err := b.clientWGSpec(ctx, master, spec.WGServer)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	ms.ClientWG = cwSpec

	autoSuspend := b.throughputAutoSuspend(ctx)

	// dnsUpstreams collects the active exit blockys (mgmt addrs) the master-tier
	// resolver forwards public queries to (ADR-0024). Built from the same membership
	// as the LB group — registered, non-decommissioned exits — so a new exit auto-joins
	// the resolver set as soon as it registers (drain doesn't remove it: a drained
	// exit's blocky still resolves, and keeping it avoids an empty upstream group).
	var dnsUpstreams []string

	for _, exit := range b.fleet.Exits {
		exitNode, exitPub := b.lookupPubKey(ctx, exit.Name)
		if exitPub == "" {
			b.log.Warn("exit public key not yet registered; omitting from master mihomo proxies",
				"master", master.Name, "exit", exit.Name)
			continue
		}
		if exitNode.Decommission {
			// A decommissioning exit is going away — drop it from the master
			// entirely (not just out of the LB group, which is what Drain does).
			continue
		}
		masterAddr, err := nthHost(exit.AddressPool, masterHostIndex)
		if err != nil {
			return domain.NodeSpec{}, err
		}
		// ADR-0030: in the phases where the master dials with its per-tunnel identity,
		// it must also move to the per-tunnel address — the exit peers the two keys on
		// two distinct /32s (they cannot share one, see domain.PerTunnelKeyPhase).
		// Address and key flip together, in the single manifest step `dual`→`switch`.
		keyTunnel := ""
		if exit.PerTunnelKeyPhase().MasterUsesPerTunnelKey() {
			perTunnelAddr, aerr := nthHost(exit.AddressPool, masterPerTunnelHostIndex)
			if aerr != nil {
				return domain.NodeSpec{}, fmt.Errorf("exit %q: per-tunnel master address: %w", exit.Name, aerr)
			}
			masterAddr = perTunnelAddr
			keyTunnel = exit.Name
		}
		// Resolve the exit's public IP (the WG endpoint the master dials). Prefer the
		// store value (set by provisioning, preserved across agent Register), but fall
		// back to the manifest's public_ip / ssh.host. Without this fallback, an exit
		// that registers without a prior provisioned inventory entry — e.g. re-added
		// after a store-record delete (the drain→decommission→delete→re-add lifecycle)
		// — has an empty PublicIP, yielding an empty endpoint that fails the WHOLE
		// master mihomo render (one bad exit Errors the entire master). Mirrors the
		// master's manifest fallback below.
		exitPublicIP := exitNode.PublicIP
		if exitPublicIP == "" {
			exitPublicIP = exit.PublicIP
			if exitPublicIP == "" {
				exitPublicIP = exit.SSH.Host
			}
		}
		endpoint := ""
		var exitIP netip.Addr
		var haveIP bool
		if addr, err := netip.ParseAddr(exitPublicIP); err == nil {
			exitIP, haveIP = addr, true
			endpoint = netip.AddrPortFrom(addr, uint16(exit.WGListenPort())).String()
			// Route client traffic to this exit's OWN public IP DIRECT (master uplink),
			// never through mihomo→wg-best→WARP. Without this, SSH/management to an
			// exit's public IP breaks on a full-tunnel client, and traffic to the exit's
			// own address would hairpin out WARP back to itself. The master already
			// reaches exit endpoints directly — that is how the master↔exit tunnel dials.
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			ms.DirectCIDRs = append(ms.DirectCIDRs, netip.PrefixFrom(addr, bits).String())
		} else if exitPublicIP != "" {
			b.log.Warn("exit has unparseable public IP; omitting from master proxies",
				"exit", exit.Name, "public_ip", exitPublicIP)
			continue
		}

		// Dual-transport (ADR-0025): an exit may carry both AWG and REALITY. The
		// active transport goes into the wg-best LB group; the other is rendered as a
		// warm standby proxy (Drained). Admin drain / throughput auto-suspend (ADR-0021)
		// drains whichever is active. REALITY only becomes active once the exit has
		// published its reality pubkey AND its endpoint is dialable — until then the
		// AWG tunnel keeps carrying traffic (no flip to a not-yet-ready transport).
		baseDrained := exitNode.Drain || autoSuspend[exit.Name]
		// Reserve is orthogonal to Drained: it keys off the manifest exit name (never
		// the "-reality" proxy-name suffix), so both transports of a dual-transport
		// exit land in the same tier.
		_, isReserve := reserveExits[exit.Name]
		active := resolveActiveTransport(exit, exitNode)
		hasAWG, hasReality := false, false
		for _, t := range exit.EnabledTransports() {
			switch t.OrDefault() {
			case domain.TransportAWG:
				hasAWG = true
			case domain.TransportRealityXHTTP:
				hasReality = true
			}
		}
		realityRenderable := hasReality && haveIP && exitNode.RealityPublicKey != ""
		realityActive := active == domain.TransportRealityXHTTP && realityRenderable

		if hasAWG {
			// Same tunnel seed as the exit's interface ⇒ identical shared AWG params on
			// both ends (ADR-0005); the "master" end label gives this end its own local
			// I1-I5. mihomo is userspace WireGuard-Go, so kernel=false keeps the
			// signatures free of the <c>/<t> tags it cannot parse.
			seed := wg.TunnelSeed(exit.Name, master.Name, awgSalt)
			awg := wg.DeriveAWGParamsForEnd(seed, "master", false)
			// Mirror of the exit end in renderExitSpec — same gate, same inputs, so
			// the two ends of this tunnel cannot disagree about the AWG generation.
			if awg3Enabled(b.fleet.AWG3For(exit), exitNode) {
				awg = wg.WithAWG3(awg, seed)
			}
			ms.ExitTunnels = append(ms.ExitTunnels, domain.ExitTunnel{
				Name:            exit.Name,
				Endpoint:        endpoint,
				ServerPublicKey: exitPub,
				TunnelIP:        masterAddr.String(),
				// Must match the exit's awg0 server MTU (serverMTU in renderExitSpec); both
				// derive from this exit's link_mtu so a narrow path lowers both ends.
				MTU:             exitTunnelMTU(exit, masterAddr.Is6()),
				AWG:             &awg,
				Transport:       domain.TransportAWG,
				MasterKeyTunnel: keyTunnel,
				Drained:         baseDrained || realityActive,
				Reserve:         isReserve,
			})
		}
		if realityRenderable {
			rp := b.realityFor(exit, master.Name)
			ms.ExitTunnels = append(ms.ExitTunnels, domain.ExitTunnel{
				Name:      exit.Name + "-reality",
				Endpoint:  netip.AddrPortFrom(exitIP, uint16(rp.Port)).String(),
				Transport: domain.TransportRealityXHTTP,
				Reality: &domain.RealityTunnel{
					UUID:        rp.UUID,
					PublicKey:   exitNode.RealityPublicKey,
					ShortID:     rp.ShortID,
					ServerName:  rp.ServerName,
					Fingerprint: rp.Fingerprint,
					Mux:         rp.Mux,
					XHTTPPath:   rp.Path,
					XHTTPMode:   rp.Mode,
					Mode:        rp.RealityMode,
					EmptySNI:    rp.EmptySNI,
				},
				Drained: baseDrained || !realityActive,
				Reserve: isReserve,
			})
		}
		if exitNode.MgmtAddr != "" {
			dnsUpstreams = append(dnsUpstreams, exitNode.MgmtAddr)
		}
	}

	spec.Master = ms
	spec.DNS = b.renderMasterDNS(master, dnsUpstreams)
	return spec, nil
}

// REALITY transport derivation (ADR-0025). The UUID and short-id are derived
// deterministically from the tunnel identity so both ends — the master's vless
// proxy and the exit's xray inbound — compute identical values without
// coordination (the same model as the AWG params). The REALITY x25519 keypair is
// NOT derived here: it is generated locally on the exit, and only its public key
// is published and read back from the store.
const (
	// DefaultRealityListenPort is the exit's VLESS port when the manifest leaves it
	// unset — 443, the standard HTTPS port (least conspicuous; an earlier finding). It must
	// differ from the AWG awg0 port so both transports run warm; the AWG port is a
	// high stable-random one, so 443 does not collide.
	DefaultRealityListenPort = 443
	// DefaultRealitySNI is the camouflage SNI/dest fallback. It MUST support TLS 1.3
	// AND the X25519MLKEM768 post-quantum key exchange — modern xray/mihomo uTLS
	// clients offer mlkem768, and a dest that can't echo it fails the authorized
	// REALITY handshake ("handshake did not complete successfully"), even though the
	// plain decoy still works (proven live 2026-06-25; XTLS PR #4779). www.microsoft.com
	// does NOT support mlkem768 and must not be used. Verify any target with
	// `xray tls ping <host>`. Operators SHOULD still override per exit with an
	// ASN-plausible, inconspicuous, mlkem768-capable target.
	DefaultRealitySNI = "www.python.org"
)

type realityParams struct {
	Port        int
	UUID        string
	ShortID     string
	ServerName  string
	Dest        string
	Path        string
	Mode        string // XHTTP mode ("packet-up")
	RealityMode string // transport mode: "" / "xhttp" / "vision"
	Fingerprint string
	EmptySNI    bool
	AllowIPv6   bool
	Mux         bool
	Image       string
}

// realityFor resolves the REALITY parameters for an exit's master↔exit tunnel,
// identical on both ends (the controller owns them). Camouflage fields come from
// the manifest with safe fallbacks; UUID/short-id/path derive from the tunnel seed.
func (b *Broker) realityFor(exit config.ExitConfig, masterName string) realityParams {
	uuid, shortID := deriveRealityIDs(realitySeed(exit.Name, masterName))
	r := exit.Transports.Reality
	// Camouflage SNI/dest: per-exit override → fleet-wide default → safe built-in.
	// dest_domain+dest_port compose to "host:port" (config.DestHostPort); when unset
	// fall back to the fleet default, then to the SNI on the default HTTPS port.
	sni := firstNonEmpty(r.SNI, r.DestDomain, b.fleet.RealityDefaultSNI, DefaultRealitySNI)
	dest := firstNonEmpty(r.DestHostPort(), b.fleet.RealityDefaultDest, sni+":443")
	path := r.XHTTPPath
	if path == "" {
		path = "/" + shortID
	}
	port := r.ListenPort
	if port == 0 {
		port = DefaultRealityListenPort
	}
	image := r.Image
	if image == "" {
		image = compose.DefaultXrayImage
	}
	return realityParams{
		Port: port, UUID: uuid, ShortID: shortID, ServerName: sni,
		Dest: dest, Path: path, Mode: xray.DefaultXHTTPMode, RealityMode: r.Mode,
		Fingerprint: r.Fingerprint, EmptySNI: r.EmptySNI, AllowIPv6: r.AllowIPv6, Mux: r.Mux, Image: image,
	}
}

// resolveActiveTransport returns the exit's active master↔exit transport: the
// operator's live per-node override (Node.ActiveTransport, set from the Web UI)
// when it names one of the exit's enabled transports, else the manifest's
// active_transport (ADR-0025).
func resolveActiveTransport(exit config.ExitConfig, node domain.Node) domain.MasterTransport {
	if ov := node.ActiveTransport; ov != "" {
		for _, t := range exit.EnabledTransports() {
			if t.OrDefault() == ov.OrDefault() {
				return ov
			}
		}
	}
	return exit.ResolvedActiveTransport()
}

// ExitTransportInfo reports an exit's resolved active master↔exit transport and
// its enabled set, for the dashboard fleet list (ADR-0025). It is a cheap pure
// lookup (manifest + the node's override) — no spec render. ok=false for a
// non-exit or a node absent from the manifest.
func (b *Broker) ExitTransportInfo(node domain.Node) (active domain.MasterTransport, enabled []domain.MasterTransport, ok bool) {
	exit, found := b.findExit(node.ID)
	if !found {
		return "", nil, false
	}
	return resolveActiveTransport(exit, node).OrDefault(), exit.EnabledTransports(), true
}

func realitySeed(exitName, masterName string) string {
	return fmt.Sprintf("%s|%s|%s|reality", awgSalt, masterName, exitName)
}

// deriveRealityIDs derives a stable VLESS UUID and REALITY short-id from a seed,
// so both tunnel ends agree without the controller storing them.
func deriveRealityIDs(seed string) (uuid, shortID string) {
	sum := sha256.Sum256([]byte(seed))
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	uuid = fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	shortID = hex.EncodeToString(sum[28:32]) // 8 hex chars
	return uuid, shortID
}

// throughputAutoSuspend returns the set of exit names to auto-suspend from the LB
// group because the throughput watchdog reported their active egress sustained-
// degraded (ADR-0021). It NEVER empties the group: an exit is auto-suspended only
// if at least one PROVEN-healthy exit (reported, not degraded, not admin-drained)
// would remain — a throttled exit still beats a black hole when every node is bad.
// An exit with no status yet (Pending/Provisioning) is neither degraded nor counted
// healthy: it must not satisfy the last-exit guard, or two limping-but-reporting
// exits could be suspended in favour of one that may never come up. The degraded
// signal is the exit's own hysteresis-smoothed egress-throughput check.
func (b *Broker) throughputAutoSuspend(ctx context.Context) map[string]bool {
	degraded := make(map[string]bool)
	healthy := 0
	for _, exit := range b.fleet.Exits {
		node, pub := b.lookupPubKey(ctx, exit.Name)
		if pub == "" || node.Decommission {
			continue
		}
		st, err := b.store.GetStatus(ctx, exit.Name)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				b.log.Warn("auto-suspend: status read failed; treating exit as unknown",
					"exit", exit.Name, "err", err)
			}
			continue // no status ⇒ neither degraded nor counted toward the guard
		}
		switch {
		case st.EgressThroughputDegraded():
			degraded[exit.Name] = true
		case !node.Drain:
			healthy++
		}
	}
	if healthy == 0 {
		return nil // keep every exit in the LB rather than black-hole all clients
	}
	return degraded
}

// egressChain builds the exit's egress priority chain (ADR-0017) from its
// preferred egress plus operator-configured fallbacks: [egress, ...egress_fallback],
// de-duplicated and keeping the preferred method first. Invalid/duplicate fallbacks
// are dropped (NodeSpec.Validate rejects anything that slips through). An exit with
// no fallbacks yields a single-entry chain ⇒ no failover, exactly as before.
func egressChain(exit config.ExitConfig) []domain.EgressMethod {
	preferred := domain.EgressMethod(exit.Egress)
	chain := []domain.EgressMethod{preferred}
	seen := map[domain.EgressMethod]bool{preferred: true}
	for _, f := range exit.EgressFallback {
		m := domain.EgressMethod(f)
		if seen[m] || !m.Valid() {
			continue
		}
		seen[m] = true
		chain = append(chain, m)
	}
	return chain
}

// exitWARPMTU returns the MTU the controller assumes for an exit's WARP egress in
// its own cross-node MTU math (master↔exit MSS/sequential model): the operator's
// per-exit warp_mtu when set, else the conservative wg.DefaultWARPMTU. The agent
// may auto-probe a different value for the wgcf interface itself (the controller
// can't see that), so this stays conservative. Only meaningful for warp egress.
func exitWARPMTU(exit config.ExitConfig) int {
	if exit.WARPMTU > 0 {
		return exit.WARPMTU
	}
	return wg.DefaultWARPMTU
}

// exitLinkMTU returns the physical/path MTU of the master↔exit link: the
// operator-measured link_mtu, or DefaultPhysicalMTU (1500) when unset. The
// master↔exit AmneziaWG tunnel MTU is this minus one AWG layer (exitTunnelMTU);
// an exit on a narrow path (link_mtu < 1500) thus gets a smaller tunnel so its
// carrier packets never black-hole.
func exitLinkMTU(exit config.ExitConfig) int {
	if exit.LinkMTU > 0 {
		return exit.LinkMTU
	}
	return wg.DefaultPhysicalMTU
}

// exitTunnelMTU returns the master↔exit AmneziaWG tunnel MTU for an exit: its
// physical link MTU minus one AWG-obfuscated WG layer. Both ends of the tunnel
// (the exit's awg0 server and the master's mihomo proxy) use this same value, and
// the client interface drops to the smallest of them (clientFacingMTU) so client
// payloads never exceed what the narrowest exit's link carries.
func exitTunnelMTU(exit config.ExitConfig, ipv6 bool) int {
	return wg.TunnelMTU(exitLinkMTU(exit), true, ipv6)
}

// clientFacingMTU is the MTU the master hands to VPN clients: the minimum across
// every hop a client payload traverses. The client↔master AWG hop binds at 1360;
// each master↔exit AWG hop may be narrower if that exit's link_mtu is below 1500
//, and a warp-egress exit that pins a smaller WARP MTU lowers it
// further. Taking the min keeps client packets from fragmenting at the narrowest
// downstream hop (sequential model, ADR-0014).
func (b *Broker) clientFacingMTU() int {
	mtu := wg.FleetTunnelMTU(true, false) // client↔master AWG hop
	for _, exit := range b.fleet.Exits {
		// master↔exit AWG hop — this exit's physical link may be narrower than 1500.
		mtu = wg.MinMTU(mtu, exitTunnelMTU(exit, false))
		if domain.EgressMethod(exit.Egress) == domain.EgressWARP {
			mtu = wg.MinMTU(mtu, exitWARPMTU(exit))
		}
	}
	return mtu
}

// mihomoStrategy maps the fleet balance setting to a mihomo load-balance
// strategy. "health" has no direct mihomo equivalent, so it maps to
// consistent-hashing (sticky per-destination), which is the closest behaviour.
// mihomoStrategy normalizes the manifest's `balance` to the value the mihomo
// renderer understands for the wg-best group. "health" is a back-compat alias for
// consistent-hashing; url-test/fallback/sticky-sessions/consistent-hashing pass
// through; anything else (incl. empty) defaults to round-robin.
func mihomoStrategy(balance string) string {
	switch balance {
	case "health", "consistent-hashing":
		return "consistent-hashing"
	case "sticky-sessions", "url-test", "fallback", "round-robin":
		return balance
	default:
		return "round-robin"
	}
}

// composeSpec assembles the master's container-stack desired state. Client DNS
// defaults to the exits' mgmt addresses (where blocky listens) when the operator
// has not set it explicitly. The master's own public IP seeds wg-easy first run.
func (b *Broker) composeSpec(ctx context.Context, master config.MasterConfig) domain.ComposeSpec {
	cc := master.Compose
	dns := append([]string(nil), cc.ClientDNS...)
	if len(dns) == 0 {
		if master.DNSFilter {
			// Master-tier blocky (ADR-0024): clients use the master gateway (its own
			// address in the client pool) as their single DNS, through the tunnel.
			if addr, err := nthHost(master.ClientAWG.AddressPool, exitHostIndex); err == nil {
				dns = []string{addr.String()}
			}
		} else {
			// Pre-ADR-0024 default: clients resolve directly against the exit blockys.
			for _, exit := range b.fleet.Exits {
				if node, _ := b.lookupPubKey(ctx, exit.Name); node.MgmtAddr != "" {
					dns = append(dns, node.MgmtAddr)
				}
			}
		}
	}
	// PublicIP seeds wg-easy's INIT_HOST (the endpoint clients dial) and is needed
	// for unattended setup to complete. Prefer the discovered address from the
	// store; fall back to the manifest's public_ip so a co-located master (hand-
	// onboarded, never SSH-provisioned, so PublicIP may be unset in the store) still
	// gets a host.
	publicIP := master.PublicIP
	if node, err := b.store.GetNode(ctx, master.Name); err == nil && node.PublicIP != "" {
		publicIP = node.PublicIP
	}
	return domain.ComposeSpec{
		WGEasyImage:      config.ResolveImage(cc.WGEasyImage, cc.WGEasyTag, compose.DefaultWGEasyImage),
		MihomoImage:      config.ResolveImage(cc.MihomoImage, cc.MihomoTag, compose.DefaultMihomoImage),
		PublicIP:         publicIP,
		WGEasyWebPort:    cc.WGEasyWebPort,
		ClientDNS:        dns,
		ClientAllowedIPs: cc.ClientAllowedIPs,
	}
}

// masterCustomConfig assembles the operator's mihomo overrides + extra files.
func masterCustomConfig(master config.MasterConfig) domain.CustomConfig {
	cc := domain.CustomConfig{Overrides: master.Mihomo.Overrides}
	for _, f := range master.Mihomo.ExtraFiles {
		cc.Files = append(cc.Files, domain.ManagedFile{Path: f.Path, Content: f.Content, Secret: f.Secret})
	}
	return cc
}

func (b *Broker) renderDNS(ctx context.Context, exit config.ExitConfig) domain.DNSFilterSpec {
	if !exit.DNSFilter {
		return domain.DNSFilterSpec{}
	}
	node, _ := b.lookupPubKey(ctx, exit.Name)
	d := exit.DNS
	prometheus := true // default on (docs/DESIGN.md §9: no blind components)
	if d.Prometheus != nil {
		prometheus = *d.Prometheus
	}
	return domain.DNSFilterSpec{
		Enabled:  true,
		MgmtAddr: node.MgmtAddr, // mgmt/ZT address only, never public (docs/DESIGN.md §9)
		Ports: domain.DNSPorts{
			DNS:   d.Ports.DNS,
			TLS:   d.Ports.TLS,
			HTTPS: d.Ports.HTTPS,
			HTTP:  d.Ports.HTTP,
		},
		Upstreams:  append([]string(nil), d.Upstreams...),
		Allowlist:  append([]string(nil), d.Allowlist...),
		Prometheus: prometheus,
		Image:      config.ResolveImage(d.Image, d.Tag, compose.DefaultBlockyImage),
		Custom:     dnsCustomConfig(d),
	}
}

// renderMasterDNS builds the master-tier blocky resolver spec (ADR-0024). Its
// default upstream group is the active exit blockys (their mgmt addrs) — clients'
// public queries are forwarded there and resolved at the exit's egress; the
// operator's overrides layer on blocking + conditional local-zone mappings. The
// client-facing gateway bind is added agent-side (from MasterSpec.BindAddress, no
// wire field). Off ⇒ an empty (disabled) spec.
func (b *Broker) renderMasterDNS(master config.MasterConfig, exitUpstreams []string) domain.DNSFilterSpec {
	if !master.DNSFilter {
		return domain.DNSFilterSpec{}
	}
	d := master.DNS
	prometheus := true // default on (docs/DESIGN.md §9: no blind components)
	if d.Prometheus != nil {
		prometheus = *d.Prometheus
	}
	// Upstreams default to the active exit blockys unless the operator pins them.
	upstreams := append([]string(nil), d.Upstreams...)
	if len(upstreams) == 0 {
		upstreams = exitUpstreams
	}
	return domain.DNSFilterSpec{
		Enabled:  true,
		MgmtAddr: master.MgmtAddr, // mgmt bind; the client-gateway bind is added agent-side
		Ports: domain.DNSPorts{
			DNS:   d.Ports.DNS,
			TLS:   d.Ports.TLS,
			HTTPS: d.Ports.HTTPS,
			HTTP:  d.Ports.HTTP,
		},
		Upstreams:  upstreams,
		Allowlist:  append([]string(nil), d.Allowlist...),
		Prometheus: prometheus,
		Image:      config.ResolveImage(d.Image, d.Tag, compose.DefaultBlockyImage),
		Custom:     dnsCustomConfig(d),
	}
}

// dnsCustomConfig assembles the operator's blocky overrides + extra include files
// (the rich surface: denylists, conditional mappings, caching tuning).
func dnsCustomConfig(d config.DNSConfig) domain.CustomConfig {
	cc := domain.CustomConfig{Overrides: d.Overrides}
	for _, f := range d.ExtraFiles {
		cc.Files = append(cc.Files, domain.ManagedFile{Path: f.Path, Content: f.Content, Secret: f.Secret})
	}
	return cc
}

// lookupPubKey returns the inventory node and its registered public key (empty
// if the node is unknown or has not registered yet).
func (b *Broker) lookupPubKey(ctx context.Context, name string) (domain.Node, string) {
	node, err := b.store.GetNode(ctx, name)
	if err != nil {
		return domain.Node{}, ""
	}
	return node, node.PublicKey
}

// tunnelPubKey returns the master's per-tunnel WireGuard public key for one exit
// (ADR-0030), or "" when it has not been published yet. A store error is treated
// the same as "not yet registered": callers already tolerate a missing key by
// rendering the legacy peer, and failing the whole spec render over it would take
// the master down for a key that is only additive.
func (b *Broker) tunnelPubKey(ctx context.Context, masterName, exitName string) string {
	keys, err := b.store.ListNodeTunnelKeys(ctx, masterName)
	if err != nil {
		b.log.Warn("failed to read per-tunnel keys; falling back to the shared master key",
			"master", masterName, "exit", exitName, "err", err)
		return ""
	}
	return keys[exitName]
}

func (b *Broker) masterDirectCIDRs(m config.MasterConfig) []string {
	return append([]string(nil), m.Routing.DirectCIDRs...)
}

// masterPublicIP resolves the master's public address the same way the compose
// spec does: prefer what the store discovered, fall back to the manifest. The
// co-located master is hand-onboarded and never SSH-provisioned, so its store
// record can legitimately carry no public IP. Returns "" when neither has one.
func (b *Broker) masterPublicIP(ctx context.Context, m config.MasterConfig) string {
	if node, err := b.store.GetNode(ctx, m.Name); err == nil && node.PublicIP != "" {
		return node.PublicIP
	}
	return m.PublicIP
}

// mergeUnique concatenates a and b, dropping empties and duplicates while keeping
// first-seen order. Returns nil when the result is empty so callers preserve the
// previous "unset" semantics rather than an empty non-nil slice.
func mergeUnique(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var out []string
	for _, s := range a {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range b {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func (b *Broker) findExit(name string) (config.ExitConfig, bool) {
	for _, e := range b.fleet.Exits {
		if e.Name == name {
			return e, true
		}
	}
	return config.ExitConfig{}, false
}

func (b *Broker) findMaster(name string) (config.MasterConfig, bool) {
	for _, m := range b.fleet.Masters {
		if m.Name == name {
			return m, true
		}
	}
	return config.MasterConfig{}, false
}

// primaryMaster returns the master that fronts exits on MVP (the first one).
func (b *Broker) primaryMaster() (config.MasterConfig, bool) {
	if len(b.fleet.Masters) == 0 {
		return config.MasterConfig{}, false
	}
	return b.fleet.Masters[0], true
}

// firstNonEmpty returns the first non-empty string, or "" if all are empty.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
