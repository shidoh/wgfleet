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
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/shidoh/wgfleet/internal/compose"
	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/store"
	"github.com/shidoh/wgfleet/internal/domain"
	"github.com/shidoh/wgfleet/internal/wg"
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
	return b.store.SetNodePublicKey(ctx, nodeID, publicKey)
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
	if exit, ok := b.findExit(nodeID); ok {
		return b.renderExitSpec(ctx, exit)
	}
	if master, ok := b.findMaster(nodeID); ok {
		return b.renderMasterSpec(ctx, master)
	}
	return domain.NodeSpec{}, fmt.Errorf("keybroker: node %q not found in fleet manifest", nodeID)
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

	// The exit's server carries the master↔exit tunnel. It is AmneziaWG over its
	// own physical link, so its MTU subtracts one AWG-obfuscated layer (sequential
	// model, ADR-0014; an earlier finding).
	serverMTU := wg.FleetTunnelMTU(true, exitAddr.Is6())

	// AmneziaWG obfuscation for the master↔exit tunnel: derived deterministically
	// from the tunnel identity so both ends compute the identical shared params
	// (only Jc/Jmin/Jmax may differ; this end uses the defaults).
	var awg *domain.AWGParams
	if master, ok := b.primaryMaster(); ok {
		// Exit is the kernel-module (awg-quick) end of the master↔exit tunnel, so
		// its I1-I5 signatures may use the full CPS tag set including <c>/<t>.
		p := wg.DeriveAWGParamsForEnd(wg.TunnelSeed(exit.Name, master.Name, awgSalt), "exit", true)
		awg = &p
	}

	spec := domain.NodeSpec{
		Role:        domain.RoleExit,
		Egress:      egress,
		EgressChain: egressChain(exit),
		WGServer: domain.WGServerSpec{
			ListenPort:  port,
			AddressPool: exit.AddressPool,
			Address:     exitAddr.String(),
			MTU:         serverMTU,
			AWG:         awg,
		},
		// WARP egress rides the exit's own physical link to Cloudflare, whose path
		// MTU can be below 1500; the operator pins it per exit via
		// warp_mtu, else it is the computed 1440. The exit's WARP planner uses this.
		WARPMTU: exitWARPMTU(exit),
		DNS:     b.renderDNS(ctx, exit),
		Firewall: domain.FirewallSpec{
			ASBlacklist: exit.Firewall.ASBlacklist,
			Whitelist:   append([]string(nil), exit.Firewall.Whitelist...),
			WGPort:      port,
		},
		Exporters: domain.ExportersSpec{Node: true, WG: true, WARP: egress == domain.EgressWARP},
	}

	master, ok := b.primaryMaster()
	if !ok {
		b.log.Warn("exit has no master to peer with", "exit", exit.Name)
		return spec, nil
	}
	masterNode, masterPub := b.lookupPubKey(ctx, master.Name)
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

	// Routing intent: client traffic egresses via WARP, but management and the
	// path back to the master must stay direct (an earlier finding–#5).
	spec.Routing = domain.RoutingSpec{
		MasterIP:    masterNode.PublicIP,
		DirectCIDRs: b.masterDirectCIDRs(master),
	}
	if egress == domain.EgressWARP {
		spec.Routing.EgressInterface = "wgcf"
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
	clientAWG := wg.DeriveAWGParams(wg.TunnelSeed(master.Name, "clients", awgSalt))
	spec := domain.NodeSpec{
		Role: domain.RoleMaster,
		WGServer: domain.WGServerSpec{
			ListenPort:  master.ClientAWG.ListenPort,
			AddressPool: master.ClientAWG.AddressPool,
			// Client-facing AWG hop. Sequential model (ADR-0014): the client MTU is
			// the minimum across every hop its payload traverses — client↔master and
			// master↔exit (AWG, 1360) and exit→WARP. With default WARP (1440) the AWG
			// hop binds at 1360; if any exit pins a smaller WARP MTU, the
			// client drops to it so packets never fragment at that exit's egress.
			MTU: b.clientFacingMTU(),
			AWG: &clientAWG,
		},
		Firewall:  domain.FirewallSpec{WGPort: master.ClientAWG.ListenPort},
		Exporters: domain.ExportersSpec{Node: true, WG: true},
	}

	ms := &domain.MasterSpec{
		Balance:     mihomoStrategy(master.Routing.Balance),
		DirectCIDRs: append([]string(nil), master.Routing.DirectCIDRs...),
		DirectGeo:   append([]string(nil), master.Routing.DirectGeo...),
		SnifferSkip: append([]string(nil), master.Mihomo.SnifferSkip...),
		RedirPort:   master.Mihomo.RedirPort,
		Custom:      masterCustomConfig(master),
	}
	if addr, err := nthHost(master.ClientAWG.AddressPool, exitHostIndex); err == nil {
		ms.BindAddress = addr.String() // master's own .1 in the client pool
	}
	if master.MgmtAddr != "" {
		ms.ExternalController = master.MgmtAddr + ":9090" // Clash API on mgmt only
	}
	ms.Compose = b.composeSpec(ctx, master)

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
		endpoint := ""
		if addr, err := netip.ParseAddr(exitNode.PublicIP); err == nil {
			endpoint = netip.AddrPortFrom(addr, uint16(exit.WGListenPort())).String()
		} else if exitNode.PublicIP != "" {
			b.log.Warn("exit has unparseable public IP; omitting from master proxies",
				"exit", exit.Name, "public_ip", exitNode.PublicIP)
			continue
		}
		// Same tunnel seed as the exit's interface ⇒ identical shared AWG params on
		// both ends (ADR-0005); the "master" end label gives this end its own local
		// I1-I5. mihomo is userspace WireGuard-Go, so kernel=false keeps the
		// signatures free of the <c>/<t> tags it cannot parse.
		awg := wg.DeriveAWGParamsForEnd(wg.TunnelSeed(exit.Name, master.Name, awgSalt), "master", false)
		ms.ExitTunnels = append(ms.ExitTunnels, domain.ExitTunnel{
			Name:            exit.Name,
			Endpoint:        endpoint,
			ServerPublicKey: exitPub,
			TunnelIP:        masterAddr.String(),
			MTU:             wg.FleetTunnelMTU(true, masterAddr.Is6()),
			AWG:             &awg,
			Drained:         exitNode.Drain, // kept as a proxy, out of the LB group
		})
	}

	spec.Master = ms
	return spec, nil
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

// exitWARPMTU returns the MTU for an exit's WARP egress interface: the operator's
// per-exit warp_mtu when set, else the computed sequential value (1440). Only
// meaningful for warp egress; direct egress carries no WARP layer.
func exitWARPMTU(exit config.ExitConfig) int {
	if exit.WARPMTU > 0 {
		return exit.WARPMTU
	}
	return wg.FleetTunnelMTU(false, false)
}

// clientFacingMTU is the MTU the master hands to VPN clients: the minimum across
// every hop a client payload traverses. The fleet AWG hops bind at 1360; a
// warp-egress exit that pins a smaller WARP MTU lowers it further so
// client packets never fragment at that exit's egress. Direct-egress exits carry
// no WARP constraint and are skipped.
func (b *Broker) clientFacingMTU() int {
	mtu := wg.FleetTunnelMTU(true, false) // client↔master AWG hop (== master↔exit)
	for _, exit := range b.fleet.Exits {
		if domain.EgressMethod(exit.Egress) != domain.EgressWARP {
			continue
		}
		mtu = wg.MinMTU(mtu, exitWARPMTU(exit))
	}
	return mtu
}

// mihomoStrategy maps the fleet balance setting to a mihomo load-balance
// strategy. "health" has no direct mihomo equivalent, so it maps to
// consistent-hashing (sticky per-destination), which is the closest behaviour.
func mihomoStrategy(balance string) string {
	switch balance {
	case "round-robin":
		return "round-robin"
	case "health", "consistent-hashing":
		return "consistent-hashing"
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
		for _, exit := range b.fleet.Exits {
			if node, _ := b.lookupPubKey(ctx, exit.Name); node.MgmtAddr != "" {
				dns = append(dns, node.MgmtAddr)
			}
		}
	}
	var publicIP string
	if node, err := b.store.GetNode(ctx, master.Name); err == nil {
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

func (b *Broker) masterDirectCIDRs(m config.MasterConfig) []string {
	return append([]string(nil), m.Routing.DirectCIDRs...)
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
