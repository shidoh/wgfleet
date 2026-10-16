// Package keybroker is the controller's key registry and topology renderer. It
// realizes docs/DESIGN.md principle #2: the controller stores only public keys and
// renders each node's peer list from them — it never holds a private key.
//
// MVP topology (the reference master↔exit mesh): exits run a WG server; the
// master dials each exit. The master's client-facing AmneziaWG server (where
// real VPN clients connect) is configured separately and is not part of this
// fleet-internal peering. Every master is a peer on each exit's one interface; what
// belongs to that interface is derived from the fleet's anchor label (see exitInterface).
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
	"sort"
	"sync"
	"time"

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
// fleet-wide by bumping it.
//
// The ONE parameter this reasoning does not cover is the 3.x header-protection
// key, which is keyed on fleet.awg3_key instead — see wg.deriveHeaderProtectionKey.
const awgSalt = "wgfleet-awg-v1"

// Broker renders NodeSpecs from fleet config plus the inventory/pubkey registry.
type Broker struct {
	store store.Store
	fleet config.FleetSection
	log   *slog.Logger
	// awg3Key is the resolved fleet.awg3_key. Empty when the operator has not set
	// one, which config validation permits only while header protection is off
	// everywhere.
	awg3Key string

	// warned remembers which addressing complaints have already been logged, so a
	// standing manifest problem is announced once instead of on every render. See
	// warnOnce.
	warnMu sync.Mutex
	warned map[string]string

	// Auto-suspend hysteresis (see throughputAutoSuspend). now is injected by tests.
	now func() time.Time
	// pinConfirmed caches, per master↔exit tunnel (pinKey), the pinned address the
	// exit confirmed holding; the store has the durable copy. See confirmation.
	pinMu        sync.Mutex
	pinConfirmed map[string]pinConfirmation
	// pinCarrying is, per master↔exit tunnel (pinKey), whether its AWG tunnel was
	// carrying traffic on the last pass and since when; guarded by pinMu. See
	// carryingSince.
	pinCarrying map[string]carryTrack
	suspendMu   sync.Mutex
	suspend     map[string]*suspendTrack
	// suspendLoaded is set once the stored suspensions have been read into suspend
	// (see loadSuspensions); until then nothing may be decided from an empty map.
	suspendLoaded bool
	// suspendStored is the suspended set known to be in the store: what was loaded,
	// plus every write that succeeded since. syncSuspensions brings the store in
	// line with suspend against it. Guarded by suspendMu.
	suspendStored map[string]bool
	// syncMu serialises syncSuspensions end to end, so two renders cannot write the
	// store in one order and record the outcome in the other. Never held together
	// with suspendMu across I/O: suspendMu is taken and released inside it.
	syncMu sync.Mutex
	// suspendGuard is set while the last-healthy-exit guard overrides the suspended
	// set (no healthy exit left: every exit stays in the balancer). Guarded by suspendMu.
	suspendGuard bool
}

// suspendTrack is one exit's auto-suspend history: how long it has been degraded
// or healthy without interruption, and whether it is currently out of the balancer.
type suspendTrack struct {
	degradedSince, healthySince time.Time
	suspended                   bool
}

// Auto-suspend hysteresis, in MINUTES. The exit's own throughput watchdog already
// smooths the check over three probes (90 s), and that was the whole gate: on
// 2026-09-07 vn0's WARP path sat at the 250 KiB/s floor, its check flipped three
// times in seven minutes, and every flip re-rendered the master's mihomo config —
// a hot reload that leaks WireGuard devices, so each one cost a container restart
// and ten minutes of clients on the floor. Removing an exit from the balancer is
// an expensive act on the master; it has to be earned by minutes of evidence, and
// undone by minutes of evidence, not by one probe either way.
const (
	AutoSuspendAfter = 5 * time.Minute
	AutoReleaseAfter = 5 * time.Minute
)

// New constructs a Broker over the given store and fleet manifest.
func New(st store.Store, fleet config.FleetSection, log *slog.Logger, opts ...Option) *Broker {
	if log == nil {
		log = slog.Default()
	}
	b := &Broker{store: st, fleet: fleet, log: log, warned: make(map[string]string),
		now: time.Now, suspend: make(map[string]*suspendTrack), pinConfirmed: make(map[string]pinConfirmation)}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Option configures a Broker. Variadic so every existing three-argument caller —
// including all the tests — keeps compiling.
type Option func(*Broker)

// WithAWG3Key supplies the resolved fleet secret the 3.x header-protection key is
// derived from. Without it the broker still renders 3.x TIMERS, which need no
// secret; header protection is refused at config validation instead.
func WithAWG3Key(key string) Option {
	return func(b *Broker) { b.awg3Key = key }
}

// WithClock overrides the broker's clock; tests drive the auto-suspend
// hysteresis with it instead of waiting out real minutes.
func WithClock(now func() time.Time) Option {
	return func(b *Broker) { b.now = now }
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
		return fmt.Errorf("%q published a malformed AWG public key (want 32 bytes, base64)", nodeID)
	}
	if b.keyUnchanged(ctx, nodeID, publicKey, func(n domain.Node) string { return n.PublicKey }) {
		return nil
	}
	if err := b.refuseAnotherMastersKey(ctx, nodeID, publicKey, "shared", func(ctx context.Context, master string) (string, error) {
		_, pub, err := b.lookupPubKey(ctx, master)
		return pub, err
	}); err != nil {
		return err
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

// RegisterRealityPortalKey records the master's REALITY PORTAL x25519 public key
// (ADR-0038). Validated before the store write: it is rendered verbatim into
// every bridge's config.
func (b *Broker) RegisterRealityPortalKey(ctx context.Context, nodeID, publicKey string) error {
	if publicKey == "" {
		return fmt.Errorf("keybroker: empty reality portal public key for %q", nodeID)
	}
	if !xray.ValidPublicKey(publicKey) {
		return fmt.Errorf("keybroker: malformed reality portal public key for %q", nodeID)
	}
	if b.keyUnchanged(ctx, nodeID, publicKey, func(n domain.Node) string { return n.RealityPortalPublicKey }) {
		return nil
	}
	if err := b.store.SetNodeRealityPortalKey(ctx, nodeID, publicKey); err != nil {
		return err
	}
	b.log.Info("REALITY portal public key registered", "node", nodeID)
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

// RegisterLifelineKey records an exit's LIFELINE interface WireGuard public
// key — the identity of the reserve client-facing interface (awgl0) an exit may
// carry. Validated as a well-formed WireGuard key before storing: it is
// rendered verbatim into reserve client configs, so a malformed value from a
// CA-authenticated-but-rogue node must be refused here (same guard as the other
// WireGuard-family keys above).
func (b *Broker) RegisterLifelineKey(ctx context.Context, nodeID, publicKey string) error {
	if publicKey == "" {
		return fmt.Errorf("keybroker: empty lifeline public key for %q", nodeID)
	}
	if !wg.ValidKey(publicKey) {
		return fmt.Errorf("keybroker: malformed lifeline public key for %q", nodeID)
	}
	if b.keyUnchanged(ctx, nodeID, publicKey, func(n domain.Node) string { return n.LifelinePublicKey }) {
		return nil
	}
	if err := b.store.SetNodeLifelineKey(ctx, nodeID, publicKey); err != nil {
		return err
	}
	b.log.Info("lifeline public key registered", "node", nodeID)
	return nil
}

// clientVLESSSpec resolves a master's client-facing VLESS+REALITY+XHTTP inbound
// desired state, or nil when the transport is disabled. Camouflage falls back
// per-exit-style (manifest → fleet default → safe built-in); the issued client
// credentials come from the store (UI-managed), and empty_sni defaults ON.
func (b *Broker) clientVLESSSpec(ctx context.Context, master config.MasterConfig) (*domain.ClientVLESSServerSpec, error) {
	cv := master.ClientVLESS
	if !cv.Enabled {
		return nil, nil
	}
	sni := firstNonEmpty(cv.SNI, cv.DestDomain, b.fleet.RealityDefaultSNI, DefaultRealitySNI)
	dest := firstNonEmpty(cv.DestHostPort(), b.fleet.RealityDefaultDest, sni+":443")
	clients, err := b.store.ListVLESSClients(ctx, master.Name)
	if err != nil {
		// Fail the render rather than emit an inbound with no clients.
		//
		// This used to log a warning and carry on with nil, on the reasoning that "the
		// listener still comes up". It does — authenticating nobody. The agent applies
		// the changed config and restarts xray, so one transient store read de-issues
		// every VLESS credential until the next successful render. The client interface
		// refuses exactly this shape for exactly this reason, and the argument for
		// treating VLESS differently was that fewer people use it — a usage assumption,
		// not a safety one, and wrong in the case that matters: VLESS is the transport
		// people reach for precisely when AWG is being throttled.
		return nil, fmt.Errorf("client VLESS inbound: listing credentials: %w", err)
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
	}, nil
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
		return fmt.Errorf("%q published a malformed per-tunnel AWG public key for tunnel %q (want 32 bytes, base64)", nodeID, tunnel)
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
	if err := b.refuseAnotherMastersKey(ctx, nodeID, publicKey, "per-tunnel", func(ctx context.Context, master string) (string, error) {
		return b.tunnelPubKey(ctx, master, tunnel)
	}); err != nil {
		return err
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
	switch node, err := b.store.GetNode(ctx, nodeID); {
	case err == nil && node.Decommission:
		return domain.NodeSpec{Role: node.Role, Decommission: true}, nil
	case err != nil && !errors.Is(err, store.ErrNotFound):
		// Whether the node is flagged for decommission is not known. Rendering on
		// would be a guess, and a failure further down marked store.ErrUnreadable
		// would reach the agent as "controller unavailable" — on which it converges
		// on its cached spec, rebuilding a node that may have just been told to
		// tear down. So this is a refusal, and deliberately NOT marked unreadable
		// (%v, not %w): the agent applies nothing this pass.
		return domain.NodeSpec{}, fmt.Errorf("node %q: could not read whether it is being decommissioned: %v", nodeID, err)
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
	port := exit.WGListenPort()
	egress := domain.EgressMethod(exit.Egress)
	// The exit's own store node carries the operator's live active-transport override.
	exitNode, _, err := b.lookupPubKey(ctx, exit.Name)
	if err != nil {
		return domain.NodeSpec{}, err
	}

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
	iface, hasAnchor, err := b.exitInterface(ctx, exit, exitNode)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	var awg *domain.AWGParams
	if hasAnchor {
		// Exit is the kernel-module (awg-quick) end of the master↔exit tunnel, so
		// its I1-I5 signatures may use the full CPS tag set including <c>/<t>. The
		// generation is decided once, for both ends, in exitInterface.
		p := wg.DeriveAWGParamsForEnd(iface.seed, "exit", true)
		if iface.awg3 {
			p = wg.WithAWG3(p, iface.seed, b.awg3Key)
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

	// Reserve client-facing interface (lifeline). Rendered BEFORE the peering
	// section below, because it is not part of the master↔exit tunnel and must not
	// be lost to that section's early returns: an exit whose master is missing is
	// precisely the state the lifeline exists for.
	//
	// The port is opened only alongside the interface itself — a hole in front of a
	// listener that never comes up is the one thing worse than no reserve path.
	lifeline, err := b.lifelineSpec(ctx, exit, exitNode)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	if lifeline != nil {
		spec.Lifeline = lifeline
		spec.Firewall.LifelinePort = lifeline.ListenPort
	}

	if len(b.fleet.Masters) == 0 {
		b.log.Warn("exit has no master to peer with", "exit", exit.Name)
		return spec, nil
	}
	// Routing intent: client traffic egresses via WARP, but management and the
	// path back to every master must stay direct (an earlier finding–#5).
	//
	// The direct list an exit inherits is the base master's, exactly as before:
	// taking every master's would change where the OTHER masters' clients leave
	// from. With no base master there is none.
	var baseDirect []string
	if base, ok := b.fleet.BaseMaster(); ok {
		baseDirect = b.masterDirectCIDRs(base)
	}
	directCIDRs := mergeUnique(baseDirect, mgmtCIDRs)

	owners, err := b.keyOwners(ctx, exit, exitNode)
	if err != nil {
		return domain.NodeSpec{}, err
	}

	// One peer set per master, in manifest order.
	//
	// MasterIP resolves from the node record masterPeers ALREADY read: a second
	// store read here would have to swallow its own error, and "the store is
	// briefly busy" would then render, apply and report a spec with no route back
	// to the master — the return path silently falling into WARP, which is the
	// failure an earlier finding exists to prevent. It is also an IP literal or nothing:
	// routing.Render feeds it to `ip rule add to <X>`, which cannot resolve a name.
	type hostRoute struct {
		slot int
		cidr string
	}
	var hosts []hostRoute
	for _, master := range b.fleet.Masters {
		if !b.exitCarries(exit, exitNode, master) {
			if ferr := b.forgetConfirmation(ctx, master.Name, exit.Name); ferr != nil {
				return domain.NodeSpec{}, ferr
			}
			continue
		}
		peers, masterNode, perr := b.masterPeers(ctx, exit, exitNode, master, serverMTU)
		if perr != nil {
			return domain.NodeSpec{}, perr
		}
		for _, p := range peers {
			if b.ownsKey(owners, exit.Name, master.Name, p.PublicKey) {
				spec.Peers = append(spec.Peers, p)
			}
		}
		ip, ok := masterRoutableIP(master, masterNode)
		switch {
		case !ok:
			b.warnOnce("master-no-routable-ip:"+master.Name+"/"+exit.Name, master.PublicIP+"|"+masterNode.PublicIP,
				"master has no usable IP literal (public_ip is unset or a DNS name and the store has none); "+
					"the exit's direct route back to the master is omitted and its replies will follow the egress",
				"exit", exit.Name, "master", master.Name, "public_ip", master.PublicIP)
		case master.IsBase():
			spec.Routing.MasterIP = ip.String()
		default:
			// RoutingSpec carries one MasterIP. Every other master's return path is
			// kept off the egress by a host route, which renders to the same `ip
			// rule … lookup main`.
			hosts = append(hosts, hostRoute{master.Slot, host32(ip)})
		}
	}
	// Appended, in slot order: the rules already on the exit keep their priorities,
	// and a master coming or going is one rule coming or going.
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].slot < hosts[j].slot })
	for _, h := range hosts {
		directCIDRs = mergeUnique(directCIDRs, []string{h.cidr})
	}
	spec.Routing.DirectCIDRs = directCIDRs
	if egress == domain.EgressWARP {
		spec.Routing.EgressInterface = "wgcf"
	}

	// REALITY/XHTTP inbound desired state (ADR-0025), set when the exit runs the
	// reality transport. The shared identifiers (UUID/short-id) and camouflage match
	// the master's vless proxy because both call realityFor with the same inputs; the
	// exit generates its own x25519 keypair locally and publishes only the pubkey.
	if spec.HasTransport(domain.TransportRealityXHTTP) {
		rp := b.realityFor(exit, iface.anchor)
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
		ClientViaNetns:      master.Mihomo.ClientViaNetns,
		NetnsCIDR:           master.Mihomo.NetnsCIDR,
	}

	// The master's own node record, read ONCE for every use below (the /32 guard,
	// the compose host, and the per-exit AWG-3 gate). Errors propagate: a store
	// failure must not read as "this master has no address".
	masterNode, _, err := b.lookupPubKey(ctx, master.Name)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	// Where this master lives in every exit's pool; see the loop over exits below.
	legacyHost, perTunnelHost := domain.MasterTunnelHostIndex(master.Slot)

	// Route client traffic to the master's OWN public IP DIRECT, exactly as each
	// exit's public IP is handled below. Without it the prerouting DNAT catches
	// client TCP to the master's own address and sends it into mihomo instead of
	// letting it terminate locally: SSH and the admin UIs then hang off the proxy
	// being healthy, and every packet takes a pointless userspace round trip.
	// Found live 2026-07-20 — the DNAT guard list carried all five exits and not
	// the master, because the exit-public-IP fix was never applied to the node
	// that hosts the rule.
	if addr, ok := masterRoutableIP(master, masterNode); ok {
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		ms.DirectCIDRs = append(ms.DirectCIDRs, netip.PrefixFrom(addr, bits).String())
	} else if master.PublicIP != "" || masterNode.PublicIP != "" {
		b.warnOnce("master-no-ip-literal:"+master.Name, master.PublicIP+"|"+masterNode.PublicIP,
			"master has no public IP literal; omitting its own /32 from DIRECT cidrs "+
				"(a DNS name in public_ip is fine for clients but unusable here — set a literal, or leave the store's)",
			"master", master.Name, "public_ip", master.PublicIP, "stored", masterNode.PublicIP)
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
	ms.Compose = b.composeSpec(ctx, master, masterEndpointHost(master, masterNode))
	// Client-facing VLESS+REALITY+XHTTP inbound (a DPI-resistant alternative to the
	// client AWG). Its world-facing TCP port opens like any other public service.
	vlessSpec, verr := b.clientVLESSSpec(ctx, master)
	if verr != nil {
		return domain.NodeSpec{}, verr
	}
	ms.ClientVLESS = vlessSpec
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

	autoSuspend, err := b.throughputAutoSuspend(ctx)
	if err != nil {
		return domain.NodeSpec{}, fmt.Errorf("master %q: %w", master.Name, err)
	}

	// dnsUpstreams collects the active exit blockys (mgmt addrs) the master-tier
	// resolver forwards public queries to (ADR-0024). Built from the same membership
	// as the LB group — registered, non-decommissioned exits — so a new exit auto-joins
	// the resolver set as soon as it registers (drain doesn't remove it: a drained
	// exit's blocky still resolves, and keeping it avoids an empty upstream group).
	var dnsUpstreams []string

	for _, exit := range b.fleet.Exits {
		exitNode, exitPub, eerr := b.lookupPubKey(ctx, exit.Name)
		if eerr != nil {
			return domain.NodeSpec{}, eerr
		}
		// An exit this master renders no tunnel to at all has no pinned flow either
		// (see forgetConfirmation); each skip below drops the pair's confirmation.
		if exitPub == "" {
			b.log.Warn("exit public key not yet registered; omitting from master mihomo proxies",
				"master", master.Name, "exit", exit.Name)
			if ferr := b.forgetConfirmation(ctx, master.Name, exit.Name); ferr != nil {
				return domain.NodeSpec{}, ferr
			}
			continue
		}
		if exitNode.Decommission {
			// A decommissioning exit is going away — drop it from the master
			// entirely (not just out of the LB group, which is what Drain does).
			if ferr := b.forgetConfirmation(ctx, master.Name, exit.Name); ferr != nil {
				return domain.NodeSpec{}, ferr
			}
			continue
		}
		iface, _, ierr := b.exitInterface(ctx, exit, exitNode)
		if ierr != nil {
			return domain.NodeSpec{}, ierr
		}
		masterAddr, err := nthHost(exit.AddressPool, legacyHost)
		if err != nil {
			return domain.NodeSpec{}, err
		}
		// ADR-0030: in the phases where the master dials with its per-tunnel identity,
		// it must also move to the per-tunnel address — the exit peers the two keys on
		// two distinct /32s (they cannot share one, see domain.PerTunnelKeyPhase).
		// Address and key flip together, in the single manifest step `dual`→`switch`.
		keyTunnel := ""
		if exit.PerTunnelKeyPhase().MasterUsesPerTunnelKey() {
			perTunnelAddr, aerr := nthHost(exit.AddressPool, perTunnelHost)
			if aerr != nil {
				return domain.NodeSpec{}, fmt.Errorf("exit %q: per-tunnel master address: %w", exit.Name, aerr)
			}
			masterAddr = perTunnelAddr
			keyTunnel = exit.Name
		}
		// Resolve the exit's public IP (the WG endpoint the master dials): the
		// manifest's public_ip, else its ssh.host (the documented default), else the
		// store — first source that is an IP LITERAL, since both the endpoint and the
		// /32 below go somewhere that cannot resolve a name.
		//
		// The MANIFEST decides, in the order docs/manifest.md promises. Nothing
		// discovers this address — see masterEndpointHost for why the store row is a
		// copy that only a re-provision refreshes — so reading the store first pinned
		// the endpoint to whatever the node had on the day it was onboarded: an exit
		// that changed address stayed unreachable however the manifest was edited, and
		// the master's tunnel to it stayed down (reported against 0.1.6). Changing a
		// node's address is an ordinary event, and it must take effect on the next
		// render.
		//
		// The store is still the last resort so an exit the manifest describes by name
		// only — hand-onboarded, or re-added after a store-record delete in the
		// drain→decommission→delete→re-add lifecycle — renders SOME endpoint: an empty
		// one fails the WHOLE master mihomo render, one bad exit Erroring the master.
		if exit.PublicIP != "" && !isIPLiteral(exit.PublicIP) {
			b.warnOnce("exit-public-ip-not-literal:"+exit.Name, exit.PublicIP,
				"exit public_ip is not an IP address; the master cannot dial a name here, "+
					"falling back to ssh.host and then the stored address",
				"exit", exit.Name, "public_ip", exit.PublicIP)
		}
		exitIP, haveIP := firstIPLiteral(exit.PublicIP, exit.SSH.Host, exitNode.PublicIP)
		endpoint := ""
		switch {
		case haveIP:
			endpoint = netip.AddrPortFrom(exitIP, uint16(exit.WGListenPort())).String()
			// Route client traffic to this exit's OWN public IP DIRECT (master uplink),
			// never through mihomo→wg-best→WARP. Without this, SSH/management to an
			// exit's public IP breaks on a full-tunnel client, and traffic to the exit's
			// own address would hairpin out WARP back to itself. The master already
			// reaches exit endpoints directly — that is how the master↔exit tunnel dials.
			bits := 32
			if exitIP.Is6() {
				bits = 128
			}
			ms.DirectCIDRs = append(ms.DirectCIDRs, netip.PrefixFrom(exitIP, bits).String())
		case exit.PublicIP != "" || exit.SSH.Host != "" || exitNode.PublicIP != "":
			b.warnOnce("exit-no-usable-ip:"+exit.Name,
				exit.PublicIP+"|"+exit.SSH.Host+"|"+exitNode.PublicIP,
				"exit has no usable public IP (nothing in public_ip, ssh.host or the stored "+
					"address parses as one); omitting from master proxies",
				"exit", exit.Name, "public_ip", exit.PublicIP, "ssh_host", exit.SSH.Host,
				"stored", exitNode.PublicIP)
			if ferr := b.forgetConfirmation(ctx, master.Name, exit.Name); ferr != nil {
				return domain.NodeSpec{}, ferr
			}
			continue
		default:
			// Every source empty. Left to fail the render rather than silently dropping
			// the exit: this is a node nobody ever gave an address, not a node whose
			// address went bad, and the master's mihomo render says so loudly.
			b.warnOnce("exit-no-address:"+exit.Name, "empty",
				"exit has no public address at all: public_ip, ssh.host and the stored "+
					"address are all empty; the master render will fail until one is set",
				"exit", exit.Name)
		}
		// An exit dialled over the management overlay is almost always an accident:
		// ssh.host is repointed there when a node's direct path is black-holed (the
		// documented workaround), and with public_ip unset that address silently
		// becomes the tunnel endpoint too — the tunnel comes UP, every check stays
		// green, and throughput collapses to the overlay's ceiling. an earlier finding.
		if haveIP && exit.PublicIP == "" && b.inMgmtOverlay(exitIP) {
			b.warnOnce("exit-endpoint-on-overlay:"+exit.Name, endpoint,
				"exit endpoint is a management-overlay address (public_ip unset, taken from ssh.host); "+
					"the master↔exit tunnel will run over the overlay — declare public_ip to make it "+
					"a decision instead of a default (the same address is fine)",
				"exit", exit.Name, "endpoint", endpoint)
		}

		// Dual-transport (ADR-0025): an exit may carry both AWG and REALITY. The
		// active transport goes into the wg-best LB group; the other is rendered as a
		// warm standby proxy (Drained). Admin drain / throughput auto-suspend (ADR-0021)
		// drains whichever is active. REALITY only becomes active once the exit has
		// published its reality pubkey AND its endpoint is dialable — until then the
		// AWG tunnel keeps carrying traffic (no flip to a not-yet-ready transport).
		baseDrained := exitNode.Drain || exit.Drain || autoSuspend[exit.Name]
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
		// The exit holds no peer for this master yet (its agent is too old to take
		// one in place): an AWG proxy to it would never handshake, and would sit in
		// the group being probed and held out. REALITY needs no peer on the exit.
		if hasAWG && !b.exitCarries(exit, exitNode, master) {
			hasAWG = false
		}
		// Nor does it hold one under a key an earlier master presents there too (see
		// keyOwners): this master would dial with a key whose peer answers on the
		// other's address.
		if hasAWG {
			peered, perr := b.peeredOn(ctx, exit, exitNode, master, masterNode)
			if perr != nil {
				return domain.NodeSpec{}, perr
			}
			hasAWG = peered
		}
		// No AmneziaWG tunnel from this master to this exit, for whichever reason
		// above: armedMasterAddr is not reached, so the pair's confirmation is
		// dropped here (see forgetConfirmation).
		if !hasAWG {
			if ferr := b.forgetConfirmation(ctx, master.Name, exit.Name); ferr != nil {
				return domain.NodeSpec{}, ferr
			}
		}
		realityRenderable := hasReality && haveIP && exitNode.RealityPublicKey != ""
		realityActive := active == domain.TransportRealityXHTTP && realityRenderable

		if hasAWG {
			armed, aerr := b.armedMasterAddr(ctx, exit, master, exitNode, masterNode)
			if aerr != nil {
				return domain.NodeSpec{}, aerr
			}
			// The exit's interface decides the shared parameters and the generation;
			// this end only chooses its own local decoy. mihomo is userspace
			// WireGuard-Go, so kernel=false keeps the signatures free of <c>/<t>.
			awg := wg.DeriveAWGParamsForEnd(iface.seed, masterEndLabel(master), false)
			if iface.awg3 {
				awg = wg.WithAWG3(awg, iface.seed, b.awg3Key)
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
				MasterAddr:      armed,
			})
		}
		if realityRenderable {
			rp := b.realityFor(exit, iface.anchor)
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
func (b *Broker) throughputAutoSuspend(ctx context.Context) (map[string]bool, error) {
	// What was suspended before this process started has to be known first.
	// Deciding from an empty history would put every suspended exit back into the
	// balancer — the re-render the state is stored to avoid — so an unreadable
	// store fails the render: the master's agent applies nothing that pass and its
	// data plane stays as it is.
	if err := b.loadSuspensions(ctx); err != nil {
		return nil, err
	}
	degraded := make(map[string]bool)
	var present, unknown []string
	healthy := 0
	for _, exit := range b.fleet.Exits {
		node, pub, err := b.lookupPubKey(ctx, exit.Name)
		if err != nil {
			// Deciding from an inventory we could not read is exactly the kind of
			// guess this function must not make — in either direction. Nothing is
			// suspended and nothing returned this pass: the set stays what it was.
			b.log.Warn("auto-suspend: inventory read failed; the suspended set is left as it is this pass",
				"exit", exit.Name, "err", err)
			return b.suspendedNow(), nil
		}
		if pub == "" || node.Decommission {
			continue
		}
		st, err := b.store.GetStatus(ctx, exit.Name)
		if errors.Is(err, store.ErrNotFound) {
			continue // no status ⇒ neither degraded nor counted toward the guard
		}
		if err != nil {
			// One failed read is not an exit that left the fleet: it keeps whatever
			// it was — suspended or not, with its clocks — until it can be read.
			b.log.Warn("auto-suspend: status read failed; the exit keeps its state this pass",
				"exit", exit.Name, "err", err)
			unknown = append(unknown, exit.Name)
			continue
		}
		present = append(present, exit.Name)
		switch {
		case st.EgressThroughputDegraded():
			degraded[exit.Name] = true
		case !node.Drain && !exit.Drain:
			healthy++
		}
	}
	suspended := b.trackSuspensions(ctx, degraded, present, unknown)
	b.suspendMu.Lock()
	b.suspendGuard = healthy == 0
	b.suspendMu.Unlock()
	if healthy == 0 {
		return nil, nil // keep every exit in the LB rather than black-hole all clients
	}
	return suspended, nil
}

// suspendedNow is the suspended set as it stands, without assessing anything.
func (b *Broker) suspendedNow() map[string]bool {
	b.suspendMu.Lock()
	defer b.suspendMu.Unlock()
	if b.suspendGuard {
		return nil
	}
	out := make(map[string]bool)
	for name, t := range b.suspend {
		if t.suspended {
			out[name] = true
		}
	}
	return out
}

// loadSuspensions reads the stored suspensions into memory, once per process. A
// failed read is retried on the next render: it never settles on "none".
func (b *Broker) loadSuspensions(ctx context.Context) error {
	b.suspendMu.Lock()
	loaded := b.suspendLoaded
	b.suspendMu.Unlock()
	if loaded {
		return nil
	}
	stored, err := b.store.ListAutoSuspended(ctx)
	if err != nil {
		return fmt.Errorf("auto-suspend: stored suspensions: %w: %w", store.ErrUnreadable, err)
	}
	b.suspendMu.Lock()
	defer b.suspendMu.Unlock()
	if b.suspendLoaded {
		return nil
	}
	if b.suspend == nil {
		b.suspend = make(map[string]*suspendTrack, len(stored))
	}
	b.suspendStored = make(map[string]bool, len(stored))
	for name := range stored {
		b.suspendStored[name] = true
		// Suspended, with both clocks at zero: it returns after AutoReleaseAfter of
		// health counted from now, the same evidence any release asks for.
		if b.suspend[name] == nil {
			b.suspend[name] = &suspendTrack{suspended: true}
		}
	}
	b.suspendLoaded = true
	return nil
}

// trackSuspensions turns this pass's degraded set into the suspended set, with
// hysteresis: an exit is suspended only after AutoSuspendAfter of continuous
// degradation and released only after AutoReleaseAfter of continuous health.
// Exits not in present are forgotten. Every transition is logged — the previous
// version changed the master's data plane without a line anywhere.
func (b *Broker) trackSuspensions(ctx context.Context, degraded map[string]bool, present, unknown []string) map[string]bool {
	// The store is brought in line after the lock is released: suspendMu is not
	// held across I/O. It is a reconcile, not a log of transitions — what memory
	// holds is compared with what is known to be stored on EVERY pass, so a write
	// that failed is simply still owed on the next one.
	defer b.syncSuspensions(ctx)
	b.suspendMu.Lock()
	defer b.suspendMu.Unlock()
	now := b.now()
	keep := make(map[string]*suspendTrack, len(present))
	out := make(map[string]bool)
	for _, name := range present {
		t := b.suspend[name]
		if t == nil {
			t = &suspendTrack{}
		}
		keep[name] = t
		if degraded[name] {
			t.healthySince = time.Time{}
			if t.degradedSince.IsZero() {
				t.degradedSince = now
			}
			if !t.suspended && now.Sub(t.degradedSince) >= AutoSuspendAfter {
				t.suspended = true
				b.log.Warn("auto-suspend: exit removed from the load balancer",
					"exit", name, "degraded_for", now.Sub(t.degradedSince).Round(time.Second))
			}
		} else {
			t.degradedSince = time.Time{}
			if t.healthySince.IsZero() {
				t.healthySince = now
			}
			if t.suspended && now.Sub(t.healthySince) >= AutoReleaseAfter {
				t.suspended = false
				b.log.Info("auto-suspend: exit returned to the load balancer",
					"exit", name, "healthy_for", now.Sub(t.healthySince).Round(time.Second))
			}
		}
		if t.suspended {
			out[name] = true
		}
		b.log.Debug("auto-suspend: exit assessed", "exit", name, "degraded", degraded[name],
			"suspended", t.suspended, "degraded_since", t.degradedSince, "healthy_since", t.healthySince)
	}
	// An exit whose status could not be read this pass is carried over untouched.
	for _, name := range unknown {
		if t := b.suspend[name]; t != nil {
			keep[name] = t
			if t.suspended {
				out[name] = true
			}
		}
	}
	// An exit that left the inventory is forgotten here, and syncSuspensions drops
	// its stored suspension with it: kept, it would come back suspended after a
	// restart on no evidence.
	b.suspend = keep
	return out
}

// syncSuspensions writes the difference between the suspended set in memory and
// the one known to be in the store. A failed write is logged and stays owed.
func (b *Broker) syncSuspensions(ctx context.Context) {
	// The render's context may be cancelled the moment the caller hangs up; the
	// transition happened either way and has to reach the store.
	ctx = context.WithoutCancel(ctx)
	b.syncMu.Lock()
	defer b.syncMu.Unlock()
	b.suspendMu.Lock()
	var set, drop []string
	for name, t := range b.suspend {
		if t.suspended && !b.suspendStored[name] {
			set = append(set, name)
		}
	}
	for name := range b.suspendStored {
		if t := b.suspend[name]; t == nil || !t.suspended {
			drop = append(drop, name)
		}
	}
	b.suspendMu.Unlock()

	stored := func(name string, is bool) {
		b.suspendMu.Lock()
		defer b.suspendMu.Unlock()
		if b.suspendStored == nil {
			b.suspendStored = make(map[string]bool)
		}
		if is {
			b.suspendStored[name] = true
		} else {
			delete(b.suspendStored, name)
		}
	}
	for _, name := range set {
		if err := b.store.SetAutoSuspended(ctx, name, b.now()); err != nil {
			b.warnOnce("auto-suspend-set:"+name, err.Error(),
				"auto-suspend: could not store the suspension; retried every pass — until it is stored, a controller restart would return the exit to the load balancer",
				"exit", name, "err", err)
			continue
		}
		b.forgetWarned("auto-suspend-set:" + name)
		stored(name, true)
	}
	for _, name := range drop {
		if err := b.store.ClearAutoSuspended(ctx, name); err != nil {
			b.warnOnce("auto-suspend-clear:"+name, err.Error(),
				"auto-suspend: could not clear the stored suspension; retried every pass — until it is cleared, a controller restart would keep the exit out of the load balancer until it has been healthy for AutoReleaseAfter",
				"exit", name, "err", err)
			continue
		}
		b.forgetWarned("auto-suspend-clear:" + name)
		stored(name, false)
	}
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

// clientResolvers is the fleet's answer to "what DNS does a client of this master
// use", for every renderer that has to answer it.
//
// It used to live inline in composeSpec, which meant it reached wg-easy's clients
// and nobody else: the managed client interface asked MasterConfig.ClientAWGDNS(),
// whose fallback is the RAW compose.client_dns manifest key rather than this
// derivation. That key is commented out in every shipped example — precisely
// because it "defaults to the exits' mgmt addresses" — so a manifest that turned on
// client_awg.managed rendered client configs with no `DNS =` line at all, and every
// phone quietly kept its carrier resolver. ADR-0024's two-tier DNS stopped at the
// door of the component that replaced wg-easy.
//
// One derivation, one answer, both renderers.
func (b *Broker) clientResolvers(ctx context.Context, master config.MasterConfig) []string {
	if dns := master.ClientAWGDNS(); len(dns) > 0 {
		return dns
	}
	if master.DNSFilter {
		// Master-tier blocky (ADR-0024): clients use the master gateway (its own
		// address in the client pool) as their single DNS, through the tunnel.
		if addr, err := nthHost(master.ClientAWG.AddressPool, exitHostIndex); err == nil {
			return []string{addr.String()}
		}
		return nil
	}
	// Pre-ADR-0024 default: clients resolve directly against the exit blockys.
	var dns []string
	for _, exit := range b.fleet.Exits {
		if node, _, err := b.lookupPubKey(ctx, exit.Name); err == nil && node.MgmtAddr != "" {
			dns = append(dns, node.MgmtAddr)
		}
	}
	return dns
}

// composeSpec assembles the master's container-stack desired state. Client DNS
// defaults to the exits' mgmt addresses (where blocky listens) when the operator
// has not set it explicitly. The master's own public IP seeds wg-easy first run.
func (b *Broker) composeSpec(ctx context.Context, master config.MasterConfig, publicIP string) domain.ComposeSpec {
	cc := master.Compose
	dns := b.clientResolvers(ctx, master)
	// publicIP seeds wg-easy's INIT_HOST (the endpoint clients dial) and is needed
	// for unattended setup to complete. Resolved by the caller from the master's
	// node record it already holds (masterEndpointHost), so a DNS name survives.
	return domain.ComposeSpec{
		WGEasyImage:      config.ResolveImage(cc.WGEasyImage, cc.WGEasyTag, compose.DefaultWGEasyImage),
		MihomoImage:      config.ResolveImage(cc.MihomoImage, cc.MihomoTag, compose.DefaultMihomoImage),
		PublicIP:         publicIP,
		WGEasyWebPort:    cc.WGEasyWebPort,
		ClientDNS:        dns,
		ClientAllowedIPs: cc.ClientAllowedIPs,
		NetnsHolderImage: cc.NetnsHolderImage,
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
	node, _, _ := b.lookupPubKey(ctx, exit.Name)
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
	d := b.fleet.MasterDNSFor(master)
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

// lookupPubKey returns the inventory node and its registered public key.
//
// "Not registered yet" and "we could not find out" are DIFFERENT answers and this
// used to return the same thing for both — a zero Node and an empty key, for
// ErrNotFound, a locked database and a cancelled context alike. Callers read that
// as "no key yet", which is a legitimate bootstrap state, and rendered a spec
// around it: an exit with no master peer, or a tunnel gated down to AWG 2.0. Those
// specs are VALID, so nothing downstream rejects them; the exit's planner sees a
// changed awg0.conf and runs awg-quick down + up, raising a tunnel that leads
// nowhere. A transient store error would take the whole data plane with it.
//
// So ErrNotFound alone keeps the old meaning — (zero node, "", nil), the bootstrap
// case a caller may legitimately render around. Every other error is returned, and
// the spec render fails: the node keeps its last-good config, which is what "we
// could not find out" has to mean. Same rule the client leg already follows.
func (b *Broker) lookupPubKey(ctx context.Context, name string) (domain.Node, string, error) {
	node, err := b.store.GetNode(ctx, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return domain.Node{}, "", nil
	case err != nil:
		return domain.Node{}, "", fmt.Errorf("reading %q from the inventory: %w", name, err)
	}
	return node, node.PublicKey, nil
}

// tunnelPubKey returns the master's per-tunnel WireGuard public key for one exit
// (ADR-0030), or "" when it has not been published yet.
//
// "Not published yet" and "the store could not answer" are different facts and must
// not share a return value. The first is ordinary — the master publishes the key
// after it first sees the exit in its own spec — and the caller handles it. The
// second used to collapse into the same empty string, and in phase `on` the legacy
// peer is no longer rendered, so ONE sqlite busy or IO error during a render pass
// produced an exit spec with no master peer at all. The agent applies that, and the
// master↔exit tunnel drops for every user until a later pass happens to succeed. A
// failed read is a failed render.
func (b *Broker) tunnelPubKey(ctx context.Context, masterName, exitName string) (string, error) {
	keys, err := b.store.ListNodeTunnelKeys(ctx, masterName)
	if err != nil {
		return "", fmt.Errorf("read per-tunnel keys for master %q: %w", masterName, err)
	}
	return keys[exitName], nil
}

func (b *Broker) masterDirectCIDRs(m config.MasterConfig) []string {
	return append([]string(nil), m.Routing.DirectCIDRs...)
}

// masterEndpointHost resolves the host END USERS dial the master at: the
// manifest's public_ip when the operator declared one, else whatever the store
// carries. It may be a DNS NAME — docs/master-migration.md recommends exactly
// that, so a future move of the master is a DNS record change instead of a
// re-issue of every client profile.
//
// The manifest wins because it is the only place this value is ever DECLARED —
// nothing discovers it. The agent's Register sends a public IP only when started
// with --public-ip, which no unit we install does, so a store row is a copy of
// the manifest taken at provisioning time and refreshed only by another one.
// Preferring it meant an operator could change public_ip, restart the
// controller, and change nothing: the master kept dialing the address the node
// had on the day it was onboarded, and the tunnel stayed down (reported against
// 0.1.6). The store remains the fallback: a co-located master is hand-onboarded
// and never SSH-provisioned, so its manifest entry may legitimately carry no
// public_ip while the store does. Returns "" when neither has one.
//
// Unlike an exit's, this resolution does NOT fall back to ssh.host. This is the
// address end users dial, and ssh.host is often the management overlay (the
// documented workaround for a black-holed direct path) — clientcfg.EndpointHost
// refuses it for the same reason, and it must not sneak in through here.
func masterEndpointHost(m config.MasterConfig, node domain.Node) string {
	if m.PublicIP != "" {
		return m.PublicIP
	}
	return node.PublicIP
}

// masterRoutableIP resolves the master's address for the KERNEL: the exit's
// "traffic back to the master stays on the main table" ip-rule and
// the master's own /32 in the DNAT guard list.
//
// It is deliberately not masterEndpointHost: that one may hold a DNS name, and
// `ip rule add to <name>` does not resolve — the step is not best-effort, so a
// name there fails every WARP exit's routing reconcile on every pass and leaves
// an earlier finding's rule uninstalled fleet-wide. So take the first source that is an
// IP LITERAL: a name in public_ip keeps serving clients while the kernel-level
// guards fall back to the address the store holds.
func masterRoutableIP(m config.MasterConfig, node domain.Node) (netip.Addr, bool) {
	return firstIPLiteral(m.PublicIP, node.PublicIP)
}

// firstIPLiteral returns the first candidate that parses as an IP address.
// Empty candidates and DNS names are skipped rather than fatal, so one unusable
// source does not cost a node the address another source has.
func firstIPLiteral(cands ...string) (netip.Addr, bool) {
	for _, c := range cands {
		if addr, err := netip.ParseAddr(c); err == nil {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// inMgmtOverlay reports whether addr falls inside the management overlay — either
// the declared mgmt_subnet or, when there is none, one of the nodes' own mgmt
// addresses (MgmtCIDRs renders those as /32s). Used to catch an exit whose tunnel
// endpoint has quietly become its overlay address; see an earlier finding.
func (b *Broker) inMgmtOverlay(addr netip.Addr) bool {
	for _, c := range b.fleet.MgmtCIDRs() {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// warnOnce logs msg the first time this key is seen with this detail, and again
// only when the detail changes. Every one of its callers reports a manifest the
// operator has to go and edit — a standing condition, not a transient one — and a
// spec renders per node every ~30s, so logging on each pass buried the fleet's
// real events under thousands of identical lines a day. That is the same churn
// Register was fixed for; do not reintroduce it by warning in a render loop.
func (b *Broker) warnOnce(key, detail, msg string, args ...any) {
	b.logOnce(slog.LevelWarn, key, detail, msg, args...)
}

// errorOnce is warnOnce for a standing condition that has a node cut off.
func (b *Broker) errorOnce(key, detail, msg string, args ...any) {
	b.logOnce(slog.LevelError, key, detail, msg, args...)
}

// forgetWarned makes the next warnOnce under key speak again: the condition it
// reported is over, so the same failure coming back is news.
func (b *Broker) forgetWarned(key string) {
	b.warnMu.Lock()
	delete(b.warned, key)
	b.warnMu.Unlock()
}

func (b *Broker) logOnce(level slog.Level, key, detail, msg string, args ...any) {
	b.warnMu.Lock()
	if prev, seen := b.warned[key]; seen && prev == detail {
		b.warnMu.Unlock()
		return
	}
	b.warned[key] = detail
	b.warnMu.Unlock()
	b.log.Log(context.Background(), level, msg, args...)
}

// isIPLiteral reports whether s is an IP address rather than a DNS name.
func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
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

// firstNonEmpty returns the first non-empty string, or "" if all are empty.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
